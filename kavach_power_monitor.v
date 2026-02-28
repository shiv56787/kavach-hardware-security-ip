

`timescale 1ns / 1ps

// ============================================================
// Top Module: kavach_power_monitor
// ============================================================
module kavach_power_monitor #(
    // ADC width for voltage and current samples
    parameter ADC_WIDTH     = 12,

    // EWMA shift factor: alpha = 1/2^EWMA_SHIFT
    // EWMA_SHIFT=4 => alpha ~0.0625 (slow adaptation)
    // EWMA_SHIFT=2 => alpha ~0.25  (fast adaptation)
    parameter EWMA_SHIFT    = 4,

    // Threat threshold: deviation above baseline (in ADC counts)
    parameter VOLT_THRESH   = 12'd200,   // ~5% of 4096
    parameter CURR_THRESH   = 12'd150,

    // Glitch pulse width detector (clock cycles)
    parameter GLITCH_WIN    = 8'd8,

    // Accumulator width to avoid overflow in EWMA
    parameter ACCUM_WIDTH   = ADC_WIDTH + EWMA_SHIFT
)(
    // ── Clock & Reset ────────────────────────────────────────
    input  wire                  clk,        // System clock
    input  wire                  rst_n,      // Active-low reset

    // ── ADC Inputs (from on-chip ADC or sensor ring) ─────────
    input  wire [ADC_WIDTH-1:0]  vdd_sample, // Voltage sample
    input  wire [ADC_WIDTH-1:0]  idd_sample, // Current sample
    input  wire                  sample_valid,// New sample strobe

    // ── Calibration / Runtime Config ─────────────────────────
    input  wire [ADC_WIDTH-1:0]  volt_thresh_cfg, // Override threshold
    input  wire [ADC_WIDTH-1:0]  curr_thresh_cfg,
    input  wire                  use_cfg_thresh,  // 1 = use above

    // ── Outputs to Threat Classifier ─────────────────────────
    output reg                   volt_anomaly,    // Voltage deviation flag
    output reg                   curr_anomaly,    // Current deviation flag
    output reg                   glitch_detected, // Fast glitch flag
    output reg  [ADC_WIDTH-1:0]  volt_baseline,   // Live EWMA baseline V
    output reg  [ADC_WIDTH-1:0]  curr_baseline,   // Live EWMA baseline I
    output reg  [ADC_WIDTH-1:0]  volt_delta,      // |sample - baseline|
    output reg  [ADC_WIDTH-1:0]  curr_delta,      // |sample - baseline|
    output reg  [1:0]            severity,        // 00=none 01=low 10=mid 11=high
    output reg                   monitor_ready    // Baseline initialised
);

// ============================================================
// Internal Signals
// ============================================================

    // Extended accumulators for EWMA (prevent truncation drift)
    reg [ACCUM_WIDTH-1:0] volt_accum;
    reg [ACCUM_WIDTH-1:0] curr_accum;

    // Absolute deltas (combinational)
    wire [ADC_WIDTH-1:0] v_delta_w;
    wire [ADC_WIDTH-1:0] i_delta_w;

    // Active thresholds (mux between default and config)
    wire [ADC_WIDTH-1:0] v_thresh_act;
    wire [ADC_WIDTH-1:0] i_thresh_act;

    // Glitch window counter
    reg  [7:0]           glitch_cnt;

    // Initialisation sample counter (warm-up period)
    reg  [7:0]           init_cnt;
    localparam INIT_SAMPLES = 8'd32; // 32 samples before flagging

    // Previous voltage sample for glitch edge detect
    reg  [ADC_WIDTH-1:0] vdd_prev;

// ============================================================
// Threshold Mux
// ============================================================
    assign v_thresh_act = use_cfg_thresh ? volt_thresh_cfg : VOLT_THRESH;
    assign i_thresh_act = use_cfg_thresh ? curr_thresh_cfg : CURR_THRESH;

// ============================================================
// Absolute Delta (combinational)
// ============================================================
    assign v_delta_w = (vdd_sample >= volt_baseline)
                       ? (vdd_sample - volt_baseline)
                       : (volt_baseline - vdd_sample);

    assign i_delta_w = (idd_sample >= curr_baseline)
                       ? (idd_sample - curr_baseline)
                       : (curr_baseline - idd_sample);

// ============================================================
// EWMA Baseline Update + Anomaly Detection
// ============================================================
// EWMA formula (integer, shift-based):
//   accum_new = accum_old - (accum_old >> SHIFT) + sample
//   baseline  = accum_new >> SHIFT
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            volt_accum    <= {ACCUM_WIDTH{1'b0}};
            curr_accum    <= {ACCUM_WIDTH{1'b0}};
            volt_baseline <= {ADC_WIDTH{1'b0}};
            curr_baseline <= {ADC_WIDTH{1'b0}};
            volt_delta    <= {ADC_WIDTH{1'b0}};
            curr_delta    <= {ADC_WIDTH{1'b0}};
            volt_anomaly  <= 1'b0;
            curr_anomaly  <= 1'b0;
            init_cnt      <= 8'h00;
            monitor_ready <= 1'b0;
            vdd_prev      <= {ADC_WIDTH{1'b0}};
        end
        else if (sample_valid) begin
            // ── EWMA Accumulator Update ───────────────────────
            volt_accum <= volt_accum
                          - (volt_accum >> EWMA_SHIFT)
                          + {{EWMA_SHIFT{1'b0}}, vdd_sample};

            curr_accum <= curr_accum
                          - (curr_accum >> EWMA_SHIFT)
                          + {{EWMA_SHIFT{1'b0}}, idd_sample};

            // ── Baseline Extract ──────────────────────────────
            volt_baseline <= volt_accum[ACCUM_WIDTH-1:EWMA_SHIFT];
            curr_baseline <= curr_accum[ACCUM_WIDTH-1:EWMA_SHIFT];

            // ── Capture Deltas ────────────────────────────────
            volt_delta <= v_delta_w;
            curr_delta <= i_delta_w;

            // ── Previous sample store (for glitch detection) ──
            vdd_prev <= vdd_sample;

            // ── Warm-up Counter ───────────────────────────────
            if (init_cnt < INIT_SAMPLES) begin
                init_cnt      <= init_cnt + 8'd1;
                monitor_ready <= 1'b0;
                volt_anomaly  <= 1'b0;
                curr_anomaly  <= 1'b0;
            end
            else begin
                monitor_ready <= 1'b1;

                // ── Anomaly Flags ─────────────────────────────
                volt_anomaly <= (v_delta_w > v_thresh_act) ? 1'b1 : 1'b0;
                curr_anomaly <= (i_delta_w > i_thresh_act) ? 1'b1 : 1'b0;
            end
        end
    end

// ============================================================
// Fast Glitch Detector
// Detects rapid voltage spike/dip within GLITCH_WIN cycles
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            glitch_cnt      <= 8'h00;
            glitch_detected <= 1'b0;
        end
        else begin
            if (sample_valid && monitor_ready) begin
                // Large single-cycle jump = glitch signature
                if (v_delta_w > (v_thresh_act >> 1)) begin
                    if (glitch_cnt < GLITCH_WIN) begin
                        glitch_cnt <= glitch_cnt + 8'd1;
                    end
                    else begin
                        glitch_detected <= 1'b1;
                    end
                end
                else begin
                    // Decay counter when no spike
                    glitch_cnt      <= (glitch_cnt > 8'h00)
                                       ? glitch_cnt - 8'd1
                                       : 8'h00;
                    glitch_detected <= 1'b0;
                end
            end
        end
    end

// ============================================================
// Severity Classifier (local, forwarded to top-level)
// 00 = No threat
// 01 = Low    (single anomaly)
// 10 = Medium (both anomalies)
// 11 = High   (glitch + anomaly)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            severity <= 2'b00;
        end
        else begin
            if (glitch_detected && (volt_anomaly || curr_anomaly))
                severity <= 2'b11;
            else if (volt_anomaly && curr_anomaly)
                severity <= 2'b10;
            else if (volt_anomaly || curr_anomaly)
                severity <= 2'b01;
            else
                severity <= 2'b00;
        end
    end

endmodule


// ============================================================
// Submodule: kavach_power_mon_tb  (Basic Simulation Testbench)
// ============================================================
// Compile separately - not synthesised into design
// Run: iverilog -o sim kavach_power_monitor.v && vvp sim
// ============================================================

`ifdef SIMULATION
module kavach_power_mon_tb;

    // Parameters
    parameter ADC_W = 12;

    // DUT signals
    reg                clk, rst_n, sample_valid, use_cfg;
    reg  [ADC_W-1:0]  vdd_s, idd_s, v_cfg, i_cfg;
    wire               v_anom, i_anom, glitch, ready;
    wire [ADC_W-1:0]  v_base, i_base, v_dlt, i_dlt;
    wire [1:0]         sev;

    // DUT instantiation
    kavach_power_monitor #(
        .ADC_WIDTH  (ADC_W),
        .EWMA_SHIFT (4),
        .VOLT_THRESH(12'd200),
        .CURR_THRESH(12'd150)
    ) dut (
        .clk             (clk),
        .rst_n           (rst_n),
        .vdd_sample      (vdd_s),
        .idd_sample      (idd_s),
        .sample_valid    (sample_valid),
        .volt_thresh_cfg (v_cfg),
        .curr_thresh_cfg (i_cfg),
        .use_cfg_thresh  (use_cfg),
        .volt_anomaly    (v_anom),
        .curr_anomaly    (i_anom),
        .glitch_detected (glitch),
        .volt_baseline   (v_base),
        .curr_baseline   (i_base),
        .volt_delta      (v_dlt),
        .curr_delta      (i_dlt),
        .severity        (sev),
        .monitor_ready   (ready)
    );

    // Clock: 100 MHz
    initial clk = 0;
    always #5 clk = ~clk;

    integer i;

    initial begin
        $dumpfile("kavach_power_mon.vcd");
        $dumpvars(0, kavach_power_mon_tb);

        // ── Reset ───────────────────────────────────────────
        rst_n = 0; sample_valid = 0;
        vdd_s = 0; idd_s = 0;
        use_cfg = 0; v_cfg = 0; i_cfg = 0;
        #20;
        rst_n = 1;
        #10;

        // ── Phase 1: Normal operation - warm up baseline ───
        $display("=== Phase 1: Normal Operation (Warm-up) ===");
        for (i = 0; i < 40; i = i+1) begin
            vdd_s = 12'd2048 + $random % 10; // ~1.0V nominal ±noise
            idd_s = 12'd1024 + $random % 8;
            sample_valid = 1; #10;
            sample_valid = 0; #10;
        end
        $display("Baseline V=%0d  I=%0d  Ready=%b", v_base, i_base, ready);

        // ── Phase 2: Voltage Glitch Attack ─────────────────
        $display("=== Phase 2: Power Glitch Attack ===");
        for (i = 0; i < 12; i = i+1) begin
            vdd_s = 12'd2048 + 12'd400; // +400 counts spike
            idd_s = 12'd1024 + 12'd300;
            sample_valid = 1; #10;
            sample_valid = 0; #10;
        end
        $display("Anomaly V=%b I=%b Glitch=%b Severity=%b",
                  v_anom, i_anom, glitch, sev);

        // ── Phase 3: Return to Normal ───────────────────────
        $display("=== Phase 3: Recovery ===");
        for (i = 0; i < 20; i = i+1) begin
            vdd_s = 12'd2048 + $random % 10;
            idd_s = 12'd1024 + $random % 8;
            sample_valid = 1; #10;
            sample_valid = 0; #10;
        end
        $display("Anomaly V=%b I=%b Glitch=%b Severity=%b",
                  v_anom, i_anom, glitch, sev);

        $display("=== Simulation Complete ===");
        #50;
        $finish;
    end

endmodule
`endif
