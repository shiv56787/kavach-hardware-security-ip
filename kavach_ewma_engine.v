
`timescale 1ns / 1ps

module kavach_ewma_engine #(
    // Number of independent EWMA channels
    // Ch0=Power-V Ch1=Power-I Ch2=Timing Ch3=Temp Ch4=IPC
    parameter NUM_CHANNELS    = 5,

    // Data width per channel
    parameter DATA_WIDTH      = 16,

    // Default EWMA shift (alpha = 1/2^SHIFT)
    // Can be overridden per-channel via shift_cfg
    parameter EWMA_SHIFT_DEF  = 4,

    // Max shift value supported
    parameter MAX_SHIFT       = 8,

    // Accumulator width = DATA_WIDTH + MAX_SHIFT
    parameter ACCUM_WIDTH     = DATA_WIDTH + MAX_SHIFT,

    // Anomaly score width
    parameter SCORE_WIDTH     = 8,

    // Cross-domain correlation window (samples)
    parameter CORR_WIN        = 16,

    // Fused threat threshold (sum of active channel severities)
    parameter FUSE_THRESH     = 8'd6
)(
    // ── Clock & Reset ────────────────────────────────────────
    input  wire                          clk,
    input  wire                          rst_n,

    // ── Per-Channel Sample Inputs ─────────────────────────────
    input  wire [DATA_WIDTH-1:0]         sample_ch0,  // Power Voltage
    input  wire [DATA_WIDTH-1:0]         sample_ch1,  // Power Current
    input  wire [DATA_WIDTH-1:0]         sample_ch2,  // Timing Period
    input  wire [DATA_WIDTH-1:0]         sample_ch3,  // Temperature
    input  wire [DATA_WIDTH-1:0]         sample_ch4,  // IPC count

    // ── Sample Valid Strobes (per channel) ────────────────────
    input  wire [NUM_CHANNELS-1:0]       sample_valid, // Bit per channel

    // ── Dynamic Alpha Config (per channel) ────────────────────
    // shift_cfg[ch] = EWMA shift for that channel (2-8)
    input  wire [MAX_SHIFT-1:0]          shift_cfg_ch0,
    input  wire [MAX_SHIFT-1:0]          shift_cfg_ch1,
    input  wire [MAX_SHIFT-1:0]          shift_cfg_ch2,
    input  wire [MAX_SHIFT-1:0]          shift_cfg_ch3,
    input  wire [MAX_SHIFT-1:0]          shift_cfg_ch4,
    input  wire                          use_cfg_shift, // 1=use above

    // ── Severity Inputs from Domain Monitors ──────────────────
    input  wire [1:0]                    sev_power,
    input  wire [1:0]                    sev_timing,
    input  wire [1:0]                    sev_temp,
    input  wire [1:0]                    sev_exec,

    // ── Baseline Outputs (per channel) ───────────────────────
    output reg  [DATA_WIDTH-1:0]         baseline_ch0,
    output reg  [DATA_WIDTH-1:0]         baseline_ch1,
    output reg  [DATA_WIDTH-1:0]         baseline_ch2,
    output reg  [DATA_WIDTH-1:0]         baseline_ch3,
    output reg  [DATA_WIDTH-1:0]         baseline_ch4,

    // ── Delta Outputs (per channel) ───────────────────────────
    output reg  [DATA_WIDTH-1:0]         delta_ch0,
    output reg  [DATA_WIDTH-1:0]         delta_ch1,
    output reg  [DATA_WIDTH-1:0]         delta_ch2,
    output reg  [DATA_WIDTH-1:0]         delta_ch3,
    output reg  [DATA_WIDTH-1:0]         delta_ch4,

    // ── Anomaly Score (per channel, 0-255) ───────────────────
    output reg  [SCORE_WIDTH-1:0]        score_ch0,
    output reg  [SCORE_WIDTH-1:0]        score_ch1,
    output reg  [SCORE_WIDTH-1:0]        score_ch2,
    output reg  [SCORE_WIDTH-1:0]        score_ch3,
    output reg  [SCORE_WIDTH-1:0]        score_ch4,

    // ── Cross-Domain Fusion Outputs ───────────────────────────
    output reg  [SCORE_WIDTH-1:0]        fused_score,   // Combined threat score
    output reg  [1:0]                    fused_severity,// 00-11
    output reg                           multi_domain_alert, // 2+ domains triggered
    output reg                           correlated_attack,  // Simultaneous trigger

    // ── Engine Status ─────────────────────────────────────────
    output reg  [NUM_CHANNELS-1:0]       channel_ready, // Per-channel warm-up done
    output reg                           engine_ready   // All channels ready
);

// ============================================================
// Internal Accumulators
// ============================================================

    reg [ACCUM_WIDTH-1:0] accum [0:NUM_CHANNELS-1];

    // Active shift per channel
    wire [MAX_SHIFT-1:0] shift [0:NUM_CHANNELS-1];

    assign shift[0] = use_cfg_shift ? shift_cfg_ch0 : EWMA_SHIFT_DEF;
    assign shift[1] = use_cfg_shift ? shift_cfg_ch1 : EWMA_SHIFT_DEF;
    assign shift[2] = use_cfg_shift ? shift_cfg_ch2 : EWMA_SHIFT_DEF;
    assign shift[3] = use_cfg_shift ? shift_cfg_ch3 : EWMA_SHIFT_DEF;
    assign shift[4] = use_cfg_shift ? shift_cfg_ch4 : EWMA_SHIFT_DEF;

    // Sample array for convenience
    wire [DATA_WIDTH-1:0] sample [0:NUM_CHANNELS-1];
    assign sample[0] = sample_ch0;
    assign sample[1] = sample_ch1;
    assign sample[2] = sample_ch2;
    assign sample[3] = sample_ch3;
    assign sample[4] = sample_ch4;

    // Baseline array
    reg [DATA_WIDTH-1:0] baseline [0:NUM_CHANNELS-1];

    // Delta (combinational)
    wire [DATA_WIDTH-1:0] delta [0:NUM_CHANNELS-1];

    // Init counters per channel
    reg [7:0] init_cnt [0:NUM_CHANNELS-1];
    localparam INIT_SAMPLES = 8'd20;

// ============================================================
// Delta Computation (combinational, per channel)
// ============================================================

    genvar g;
    generate
        for (g = 0; g < NUM_CHANNELS; g = g + 1) begin : delta_gen
            assign delta[g] = (sample[g] >= baseline[g])
                              ? (sample[g] - baseline[g])
                              : (baseline[g] - sample[g]);
        end
    endgenerate

// ============================================================
// EWMA Update - Channel 0 (Power Voltage)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            accum[0]      <= {ACCUM_WIDTH{1'b0}};
            baseline[0]   <= {DATA_WIDTH{1'b0}};
            baseline_ch0  <= {DATA_WIDTH{1'b0}};
            delta_ch0     <= {DATA_WIDTH{1'b0}};
            init_cnt[0]   <= 8'h00;
            channel_ready[0] <= 1'b0;
        end
        else if (sample_valid[0]) begin
            accum[0] <= accum[0]
                        - (accum[0] >> shift[0])
                        + {{MAX_SHIFT{1'b0}}, sample[0]};
            baseline[0]  <= accum[0][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            baseline_ch0 <= accum[0][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            delta_ch0    <= delta[0];
            if (init_cnt[0] < INIT_SAMPLES) begin
                init_cnt[0]      <= init_cnt[0] + 8'd1;
                channel_ready[0] <= 1'b0;
            end else
                channel_ready[0] <= 1'b1;
        end
    end

// ============================================================
// EWMA Update - Channel 1 (Power Current)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            accum[1]      <= {ACCUM_WIDTH{1'b0}};
            baseline[1]   <= {DATA_WIDTH{1'b0}};
            baseline_ch1  <= {DATA_WIDTH{1'b0}};
            delta_ch1     <= {DATA_WIDTH{1'b0}};
            init_cnt[1]   <= 8'h00;
            channel_ready[1] <= 1'b0;
        end
        else if (sample_valid[1]) begin
            accum[1] <= accum[1]
                        - (accum[1] >> shift[1])
                        + {{MAX_SHIFT{1'b0}}, sample[1]};
            baseline[1]  <= accum[1][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            baseline_ch1 <= accum[1][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            delta_ch1    <= delta[1];
            if (init_cnt[1] < INIT_SAMPLES) begin
                init_cnt[1]      <= init_cnt[1] + 8'd1;
                channel_ready[1] <= 1'b0;
            end else
                channel_ready[1] <= 1'b1;
        end
    end

// ============================================================
// EWMA Update - Channel 2 (Timing)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            accum[2]      <= {ACCUM_WIDTH{1'b0}};
            baseline[2]   <= {DATA_WIDTH{1'b0}};
            baseline_ch2  <= {DATA_WIDTH{1'b0}};
            delta_ch2     <= {DATA_WIDTH{1'b0}};
            init_cnt[2]   <= 8'h00;
            channel_ready[2] <= 1'b0;
        end
        else if (sample_valid[2]) begin
            accum[2] <= accum[2]
                        - (accum[2] >> shift[2])
                        + {{MAX_SHIFT{1'b0}}, sample[2]};
            baseline[2]  <= accum[2][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            baseline_ch2 <= accum[2][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            delta_ch2    <= delta[2];
            if (init_cnt[2] < INIT_SAMPLES) begin
                init_cnt[2]      <= init_cnt[2] + 8'd1;
                channel_ready[2] <= 1'b0;
            end else
                channel_ready[2] <= 1'b1;
        end
    end

// ============================================================
// EWMA Update - Channel 3 (Temperature)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            accum[3]      <= {ACCUM_WIDTH{1'b0}};
            baseline[3]   <= {DATA_WIDTH{1'b0}};
            baseline_ch3  <= {DATA_WIDTH{1'b0}};
            delta_ch3     <= {DATA_WIDTH{1'b0}};
            init_cnt[3]   <= 8'h00;
            channel_ready[3] <= 1'b0;
        end
        else if (sample_valid[3]) begin
            accum[3] <= accum[3]
                        - (accum[3] >> shift[3])
                        + {{MAX_SHIFT{1'b0}}, sample[3]};
            baseline[3]  <= accum[3][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            baseline_ch3 <= accum[3][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            delta_ch3    <= delta[3];
            if (init_cnt[3] < INIT_SAMPLES) begin
                init_cnt[3]      <= init_cnt[3] + 8'd1;
                channel_ready[3] <= 1'b0;
            end else
                channel_ready[3] <= 1'b1;
        end
    end

// ============================================================
// EWMA Update - Channel 4 (IPC / Execution)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            accum[4]      <= {ACCUM_WIDTH{1'b0}};
            baseline[4]   <= {DATA_WIDTH{1'b0}};
            baseline_ch4  <= {DATA_WIDTH{1'b0}};
            delta_ch4     <= {DATA_WIDTH{1'b0}};
            init_cnt[4]   <= 8'h00;
            channel_ready[4] <= 1'b0;
        end
        else if (sample_valid[4]) begin
            accum[4] <= accum[4]
                        - (accum[4] >> shift[4])
                        + {{MAX_SHIFT{1'b0}}, sample[4]};
            baseline[4]  <= accum[4][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            baseline_ch4 <= accum[4][ACCUM_WIDTH-1:EWMA_SHIFT_DEF];
            delta_ch4    <= delta[4];
            if (init_cnt[4] < INIT_SAMPLES) begin
                init_cnt[4]      <= init_cnt[4] + 8'd1;
                channel_ready[4] <= 1'b0;
            end else
                channel_ready[4] <= 1'b1;
        end
    end

// ============================================================
// Anomaly Score Computation (per channel, 0-255)
// Score = clipped(delta * 4 / baseline) - normalised deviation
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            score_ch0 <= 8'h00;
            score_ch1 <= 8'h00;
            score_ch2 <= 8'h00;
            score_ch3 <= 8'h00;
            score_ch4 <= 8'h00;
        end
        else begin
            // Normalised score = (delta << 2) / baseline
            // Clipped at 255 to stay in SCORE_WIDTH
            score_ch0 <= (baseline[0] != 0)
                ? ((delta[0] << 2) > 16'hFF00)
                  ? 8'hFF
                  : (delta[0] << 2) >> (DATA_WIDTH - SCORE_WIDTH)
                : 8'h00;

            score_ch1 <= (baseline[1] != 0)
                ? ((delta[1] << 2) > 16'hFF00)
                  ? 8'hFF
                  : (delta[1] << 2) >> (DATA_WIDTH - SCORE_WIDTH)
                : 8'h00;

            score_ch2 <= (baseline[2] != 0)
                ? ((delta[2] << 2) > 16'hFF00)
                  ? 8'hFF
                  : (delta[2] << 2) >> (DATA_WIDTH - SCORE_WIDTH)
                : 8'h00;

            score_ch3 <= (baseline[3] != 0)
                ? ((delta[3] << 2) > 16'hFF00)
                  ? 8'hFF
                  : (delta[3] << 2) >> (DATA_WIDTH - SCORE_WIDTH)
                : 8'h00;

            score_ch4 <= (baseline[4] != 0)
                ? ((delta[4] << 2) > 16'hFF00)
                  ? 8'hFF
                  : (delta[4] << 2) >> (DATA_WIDTH - SCORE_WIDTH)
                : 8'h00;
        end
    end

// ============================================================
// Cross-Domain Fusion Engine
// Combines severity inputs from all 4 domain monitors
// Detects simultaneous multi-domain triggers (correlated attack)
// ============================================================

    // Count active domains (severity > 0)
    wire [2:0] active_domains;
    assign active_domains = (sev_power  > 2'b00 ? 3'd1 : 3'd0)
                          + (sev_timing > 2'b00 ? 3'd1 : 3'd0)
                          + (sev_temp   > 2'b00 ? 3'd1 : 3'd0)
                          + (sev_exec   > 2'b00 ? 3'd1 : 3'd0);

    // Weighted fused score
    wire [SCORE_WIDTH-1:0] raw_fused;
    assign raw_fused = {6'b0, sev_power}
                     + {6'b0, sev_timing}
                     + {6'b0, sev_temp}
                     + {6'b0, sev_exec};

    // Correlation window counter
    reg [3:0] corr_window_cnt;
    reg [3:0] corr_hit_cnt;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fused_score        <= 8'h00;
            fused_severity     <= 2'b00;
            multi_domain_alert <= 1'b0;
            correlated_attack  <= 1'b0;
            corr_window_cnt    <= 4'h0;
            corr_hit_cnt       <= 4'h0;
        end
        else begin
            // Fused score
            fused_score <= raw_fused;

            // Multi-domain alert: 2 or more domains triggered
            multi_domain_alert <= (active_domains >= 3'd2) ? 1'b1 : 1'b0;

            // Fused severity
            if (raw_fused >= FUSE_THRESH)
                fused_severity <= 2'b11;
            else if (raw_fused >= (FUSE_THRESH >> 1))
                fused_severity <= 2'b10;
            else if (raw_fused > 8'h00)
                fused_severity <= 2'b01;
            else
                fused_severity <= 2'b00;

            // Correlated attack: multi-domain triggered within
            // CORR_WIN consecutive cycles
            if (corr_window_cnt < CORR_WIN) begin
                corr_window_cnt <= corr_window_cnt + 4'd1;
                if (active_domains >= 3'd2)
                    corr_hit_cnt <= corr_hit_cnt + 4'd1;
            end
            else begin
                corr_window_cnt   <= 4'h0;
                correlated_attack <= (corr_hit_cnt >= 4'd3) ? 1'b1 : 1'b0;
                corr_hit_cnt      <= 4'h0;
            end
        end
    end

// ============================================================
// Engine Ready - All channels warmed up
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            engine_ready <= 1'b0;
        else
            engine_ready <= &channel_ready; // AND of all channel_ready bits
    end

endmodule


