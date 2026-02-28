
`timescale 1ns / 1ps

module kavach_execution_monitor #(
    // Program counter width
    parameter PC_WIDTH          = 32,

    // Instruction retirement counter width
    parameter RETIRE_WIDTH      = 16,

    // EWMA shift for IPC (instructions per cycle) baseline
    parameter EWMA_SHIFT        = 4,

    // IPC deviation threshold (in fixed-point counts)
    parameter IPC_THRESH        = 16'd50,

    // Max allowed PC jump distance (normal branch range)
    parameter PC_JUMP_THRESH    = 32'h0000_FFFF,

    // Privilege level width (2-bit: 00=User 01=OS 10=Hyp 11=Machine)
    parameter PRIV_WIDTH        = 2,

    // Illegal privilege transition detection window
    parameter PRIV_WIN          = 4'd8,

    // Consecutive IPC violation threshold
    parameter IPC_VIOL_WIN      = 4'd5,

    // Memory region bounds (for out-of-bounds access detect)
    parameter MEM_BASE          = 32'h2000_0000,
    parameter MEM_TOP           = 32'h3FFF_FFFF,

    // Accumulator width
    parameter ACCUM_WIDTH       = RETIRE_WIDTH + EWMA_SHIFT
)(
    // ── Clock & Reset ────────────────────────────────────────
    input  wire                   clk,
    input  wire                   rst_n,

    // ── Processor Observation Bus ─────────────────────────────
    // These signals are tapped directly from processor pipeline
    input  wire [PC_WIDTH-1:0]    pc_current,      // Current PC value
    input  wire [PC_WIDTH-1:0]    pc_prev,         // Previous PC value
    input  wire                   instr_retired,   // Pulse: instruction committed
    input  wire                   instr_flushed,   // Pulse: pipeline flushed
    input  wire [PRIV_WIDTH-1:0]  priv_level,      // Current privilege level
    input  wire                   mem_access,      // Memory access strobe
    input  wire [PC_WIDTH-1:0]    mem_addr,        // Memory address accessed
    input  wire                   mem_write,       // 1=write, 0=read
    input  wire                   exception_taken, // Exception/interrupt taken
    input  wire                   nmi_taken,       // Non-maskable interrupt

    // ── Runtime Config ────────────────────────────────────────
    input  wire [PC_WIDTH-1:0]    valid_pc_base,   // Expected PC region base
    input  wire [PC_WIDTH-1:0]    valid_pc_top,    // Expected PC region top
    input  wire                   use_pc_bounds,   // 1 = enforce PC bounds

    // ── Outputs to Threat Classifier ──────────────────────────
    output reg                    ipc_anomaly,     // IPC deviation flag
    output reg                    pc_jump_anomaly, // Illegal PC jump
    output reg                    priv_anomaly,    // Illegal privilege change
    output reg                    mem_oob_anomaly, // Out-of-bounds memory
    output reg                    flush_anomaly,   // Excessive pipeline flush
    output reg                    nmi_anomaly,     // Unexpected NMI
    output reg                    exec_anomaly,    // Combined execution flag
    output reg  [RETIRE_WIDTH-1:0] ipc_baseline,  // EWMA IPC baseline
    output reg  [RETIRE_WIDTH-1:0] ipc_current,   // Current IPC window count
    output reg  [PC_WIDTH-1:0]    last_bad_pc,    // Last anomalous PC
    output reg  [1:0]             severity,        // 00=none to 11=high
    output reg                    monitor_ready
);

// ============================================================
// Internal Signals
// ============================================================

    // IPC measurement window counter (instructions per N cycles)
    reg  [RETIRE_WIDTH-1:0]  retire_cnt;      // Instructions retired this window
    reg  [15:0]              window_cnt;      // Cycle counter for window
    localparam               WINDOW_SIZE = 16'd256; // Measure IPC per 256 cycles

    // EWMA accumulator for IPC
    reg  [ACCUM_WIDTH-1:0]   ipc_accum;

    // IPC delta
    wire [RETIRE_WIDTH-1:0]  ipc_delta_w;

    // IPC violation counter
    reg  [3:0]               ipc_viol_cnt;

    // PC jump distance
    wire [PC_WIDTH-1:0]      pc_jump_dist;

    // Privilege level tracking
    reg  [PRIV_WIDTH-1:0]    priv_prev;
    reg  [3:0]               priv_viol_cnt;

    // Pipeline flush counter
    reg  [7:0]               flush_cnt;
    localparam               FLUSH_THRESH = 8'd10;

    // NMI counter
    //reg  [7:0]               nmi_cnt;
    localparam               NMI_THRESH = 8'd5;

    // Warmup
    reg  [7:0]               init_cnt;
    localparam               INIT_SAMPLES = 8'd8;

    // Window complete pulse
    wire                     window_done;

// ============================================================
// IPC Measurement Window
// Count retired instructions per WINDOW_SIZE cycles
// ============================================================

    assign window_done = (window_cnt == WINDOW_SIZE - 1);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            window_cnt  <= 16'h0000;
            retire_cnt  <= {RETIRE_WIDTH{1'b0}};
            ipc_current <= {RETIRE_WIDTH{1'b0}};
        end
        else begin
            if (window_done) begin
                // Capture and reset
                ipc_current <= retire_cnt;
                retire_cnt  <= {RETIRE_WIDTH{1'b0}};
                window_cnt  <= 16'h0000;
            end
            else begin
                window_cnt <= window_cnt + 16'd1;
                if (instr_retired)
                    retire_cnt <= retire_cnt + 1'b1;
            end
        end
    end

// ============================================================
// IPC EWMA Baseline
// ============================================================

    assign ipc_delta_w = (ipc_current >= ipc_baseline)
                         ? (ipc_current - ipc_baseline)
                         : (ipc_baseline - ipc_current);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ipc_accum     <= {ACCUM_WIDTH{1'b0}};
            ipc_baseline  <= {RETIRE_WIDTH{1'b0}};
            init_cnt      <= 8'h00;
            monitor_ready <= 1'b0;
        end
        else if (window_done) begin
            ipc_accum <= ipc_accum
                         - (ipc_accum >> EWMA_SHIFT)
                         + {{EWMA_SHIFT{1'b0}}, ipc_current};

            ipc_baseline <= ipc_accum[ACCUM_WIDTH-1:EWMA_SHIFT];

            if (init_cnt < INIT_SAMPLES) begin
                init_cnt      <= init_cnt + 8'd1;
                monitor_ready <= 1'b0;
            end
            else begin
                monitor_ready <= 1'b1;
            end
        end
    end

// ============================================================
// IPC Anomaly - Sustained Deviation
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ipc_viol_cnt <= 4'h0;
            ipc_anomaly  <= 1'b0;
        end
        else if (window_done && monitor_ready) begin
            if (ipc_delta_w > IPC_THRESH) begin
                if (ipc_viol_cnt < IPC_VIOL_WIN)
                    ipc_viol_cnt <= ipc_viol_cnt + 4'd1;
                else
                    ipc_anomaly <= 1'b1;
            end
            else begin
                ipc_viol_cnt <= 4'h0;
                ipc_anomaly  <= 1'b0;
            end
        end
    end

// ============================================================
// PC Jump Anomaly Detector
// Detects non-sequential or out-of-range PC jumps
// ============================================================

    // Absolute PC jump distance
    assign pc_jump_dist = (pc_current >= pc_prev)
                          ? (pc_current - pc_prev)
                          : (pc_prev - pc_current);

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pc_jump_anomaly <= 1'b0;
            last_bad_pc     <= {PC_WIDTH{1'b0}};
        end
        else if (monitor_ready) begin
            // Large jump = potential control flow hijack
            if (pc_jump_dist > PC_JUMP_THRESH) begin
                pc_jump_anomaly <= 1'b1;
                last_bad_pc     <= pc_current;
            end
            // PC out of valid code region
            else if (use_pc_bounds &&
                     (pc_current < valid_pc_base ||
                      pc_current > valid_pc_top)) begin
                pc_jump_anomaly <= 1'b1;
                last_bad_pc     <= pc_current;
            end
            else begin
                pc_jump_anomaly <= 1'b0;
            end
        end
    end

// ============================================================
// Privilege Level Anomaly Detector
// Detects unexpected escalation (User -> Machine without exception)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            priv_prev      <= {PRIV_WIDTH{1'b0}};
            priv_viol_cnt  <= 4'h0;
            priv_anomaly   <= 1'b0;
        end
        else if (monitor_ready) begin
            priv_prev <= priv_level;

            // Privilege escalation without exception = suspicious
            if ((priv_level > priv_prev) && !exception_taken) begin
                if (priv_viol_cnt < PRIV_WIN)
                    priv_viol_cnt <= priv_viol_cnt + 4'd1;
                else
                    priv_anomaly <= 1'b1;
            end
            else begin
                priv_viol_cnt <= 4'h0;
                if (!priv_anomaly)
                    priv_anomaly <= 1'b0;
                else if (priv_level <= priv_prev)
                    priv_anomaly <= 1'b0;
            end
        end
    end

// ============================================================
// Memory Out-of-Bounds Detector
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            mem_oob_anomaly <= 1'b0;
        end
        else if (mem_access && monitor_ready) begin
            if (mem_addr < MEM_BASE || mem_addr > MEM_TOP)
                mem_oob_anomaly <= 1'b1;
            else
                mem_oob_anomaly <= 1'b0;
        end
    end

// ============================================================
// Pipeline Flush Anomaly
// Excessive flushes = repeated fault injection attempts
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            flush_cnt     <= 8'h00;
            flush_anomaly <= 1'b0;
        end
        else if (monitor_ready) begin
            if (instr_flushed) begin
                if (flush_cnt < FLUSH_THRESH)
                    flush_cnt <= flush_cnt + 8'd1;
                else
                    flush_anomaly <= 1'b1;
            end
            else begin
                // Slow decay
                flush_cnt     <= (flush_cnt > 8'h00)
                                 ? flush_cnt - 8'd1
                                 : 8'h00;
                flush_anomaly <= 1'b0;
            end
        end
    end

// ============================================================
// NMI Anomaly Detector
// Repeated NMIs can indicate external fault injection tooling
// ============================================================

    // ============================================================
// NMI Anomaly Detector (RATE-BASED FIX)
// ============================================================

reg [7:0] nmi_window_cnt;
reg [7:0] nmi_window_timer;
localparam NMI_WINDOW = 8'd32; // cycles window

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        nmi_window_cnt   <= 8'd0;
        nmi_window_timer <= 8'd0;
        nmi_anomaly      <= 1'b0;
    end
    else if (monitor_ready) begin
        // Window timer
        if (nmi_window_timer < NMI_WINDOW)
            nmi_window_timer <= nmi_window_timer + 8'd1;
        else begin
            nmi_window_timer <= 8'd0;
            nmi_window_cnt   <= 8'd0;
            nmi_anomaly      <= 1'b0;
        end

        // Count NMIs inside window
        if (nmi_taken) begin
            nmi_window_cnt <= nmi_window_cnt + 8'd1;
            if (nmi_window_cnt >= NMI_THRESH)
                nmi_anomaly <= 1'b1;
        end
    end
end
// ============================================================
// Combined Execution Anomaly Flag
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            exec_anomaly <= 1'b0;
        else
            exec_anomaly <= ipc_anomaly    |
                            pc_jump_anomaly|
                            priv_anomaly   |
                            mem_oob_anomaly|
                            flush_anomaly  |
                            nmi_anomaly;
    end

// ============================================================
// Severity Classifier
// 00 = No threat
// 01 = Low    (IPC or flush only)
// 10 = Medium (PC jump or mem OOB)
// 11 = High   (privilege escalation or NMI + others)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            severity <= 2'b00;
        end
        else begin
            if (priv_anomaly || (nmi_anomaly && exec_anomaly))
                severity <= 2'b11;
            else if (pc_jump_anomaly || mem_oob_anomaly)
                severity <= 2'b10;
            else if (ipc_anomaly || flush_anomaly)
                severity <= 2'b01;
            else
                severity <= 2'b00;
        end
    end

endmodule


