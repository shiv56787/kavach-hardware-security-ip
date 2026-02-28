
`timescale 1ns / 1ps

module kavach_timing_monitor #(
    // Reference clock period in counts (at system clock rate)
    // Example: sys_clk=200MHz, target_clk=100MHz => REF_PERIOD=2
    parameter REF_PERIOD      = 16'd2,

    // Allowed deviation from reference period (in counts)
    parameter PERIOD_TOL      = 16'd1,

    // EWMA shift for timing baseline adaptation
    parameter EWMA_SHIFT      = 4,

    // Consecutive violation count before flagging
    parameter VIOL_THRESH     = 4'd4,

    // Frequency deviation threshold (counts)
    parameter FREQ_DEV_THRESH = 16'd3,

    // Width of period measurement counter
    parameter CNT_WIDTH       = 16
)(
    // ── Clock & Reset ────────────────────────────────────────
    input  wire                  clk,          // Fast reference clock (sys_clk)
    input  wire                  rst_n,        // Active-low reset

    // ── Monitored Clock Input ─────────────────────────────────
    input  wire                  mon_clk,      // Clock being monitored

    // ── External Timing Reference (optional) ──────────────────
    input  wire                  ref_pulse,    // Known-good reference pulse
    input  wire                  ref_valid,    // 1 = use ref_pulse

    // ── Runtime Config ────────────────────────────────────────
    input  wire [CNT_WIDTH-1:0]  period_cfg,   // Override expected period
    input  wire                  use_cfg,      // 1 = use period_cfg

    // ── Outputs to Threat Classifier ──────────────────────────
    output reg                   clk_glitch,   // Single-cycle clock anomaly
    output reg                   freq_drift,   // Sustained frequency deviation
    output reg                   timing_anomaly,// Combined timing flag
    output reg  [CNT_WIDTH-1:0]  measured_period, // Live clock period
    output reg  [CNT_WIDTH-1:0]  period_baseline, // EWMA baseline period
    output reg  [CNT_WIDTH-1:0]  period_delta,    // |measured - baseline|
    output reg  [1:0]            severity,     // 00=none 01=low 10=mid 11=high
    output reg                   monitor_ready // Baseline initialised
);

// ============================================================
// Internal Signals
// ============================================================

    // Edge detection on monitored clock
    reg  mon_clk_d1, mon_clk_d2;
    wire mon_rise;  // Rising edge of monitored clock
    wire mon_fall;  // Falling edge of monitored clock

    // Period measurement counter
    reg  [CNT_WIDTH-1:0]  period_cnt;      // Counts between edges
    reg  [CNT_WIDTH-1:0]  period_capture;  // Captured period each cycle

    // EWMA accumulator
    parameter ACCUM_WIDTH = CNT_WIDTH + EWMA_SHIFT;
    reg  [ACCUM_WIDTH-1:0] period_accum;

    // Active expected period
    wire [CNT_WIDTH-1:0]  exp_period;

    // Delta (combinational)
    wire [CNT_WIDTH-1:0]  p_delta_w;

    // Violation counter
    reg  [3:0]  viol_cnt;

    // Initialisation counter
    reg  [7:0]  init_cnt;
    localparam  INIT_SAMPLES = 8'd16;

    // Ref pulse edge detect
    reg  ref_pulse_d1;
    wire ref_rise;

// ============================================================
// Clock Edge Detection (double-flop for metastability)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            mon_clk_d1 <= 1'b0;
            mon_clk_d2 <= 1'b0;
        end else begin
            mon_clk_d1 <= mon_clk;
            mon_clk_d2 <= mon_clk_d1;
        end
    end

    assign mon_rise = ( mon_clk_d1 & ~mon_clk_d2); // 0->1 transition
    assign mon_fall = (~mon_clk_d1 &  mon_clk_d2); // 1->0 transition

// ============================================================
// Reference Pulse Edge Detection
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) ref_pulse_d1 <= 1'b0;
        else        ref_pulse_d1 <= ref_pulse;
    end

    assign ref_rise = ref_valid & ref_pulse & ~ref_pulse_d1;

// ============================================================
// Active Expected Period Mux
// ============================================================

    assign exp_period = use_cfg ? period_cfg : REF_PERIOD;

// ============================================================
// Period Measurement Counter
// Counts sys_clk ticks between rising edges of mon_clk
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            period_cnt     <= {CNT_WIDTH{1'b0}};
            period_capture <= {CNT_WIDTH{1'b0}};
            measured_period<= {CNT_WIDTH{1'b0}};
        end
        else begin
            if (mon_rise) begin
                // Capture period and restart counter
                period_capture  <= period_cnt;
                measured_period <= period_cnt;
                period_cnt      <= {CNT_WIDTH{1'b0}};
            end
            else begin
                // Saturating counter - prevent overflow
                if (period_cnt < {CNT_WIDTH{1'b1}})
                    period_cnt <= period_cnt + 1'b1;
            end
        end
    end

// ============================================================
// Absolute Delta (combinational)
// ============================================================

    assign p_delta_w = (period_capture >= period_baseline)
                       ? (period_capture - period_baseline)
                       : (period_baseline - period_capture);

// ============================================================
// EWMA Baseline Update
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            period_accum    <= {ACCUM_WIDTH{1'b0}};
            period_baseline <= {CNT_WIDTH{1'b0}};
            period_delta    <= {CNT_WIDTH{1'b0}};
            init_cnt        <= 8'h00;
            monitor_ready   <= 1'b0;
        end
        else if (mon_rise) begin
            // Update EWMA accumulator on every rising edge
            period_accum <= period_accum
                            - (period_accum >> EWMA_SHIFT)
                            + {{EWMA_SHIFT{1'b0}}, period_capture};

            // Extract baseline
            period_baseline <= period_accum[ACCUM_WIDTH-1:EWMA_SHIFT];

            // Capture delta
            period_delta <= p_delta_w;

            // Warm-up
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
// Clock Glitch Detector
// Single-cycle large deviation = glitch signature
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            clk_glitch <= 1'b0;
        end
        else if (mon_rise && monitor_ready) begin
            // Glitch = period way too short or way too long
            if (p_delta_w > PERIOD_TOL)
                clk_glitch <= 1'b1;
            else
                clk_glitch <= 1'b0;
        end
    end

// ============================================================
// Frequency Drift Detector
// Sustained deviation across multiple cycles
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            viol_cnt   <= 4'h0;
            freq_drift <= 1'b0;
        end
        else if (mon_rise && monitor_ready) begin
            if (p_delta_w > FREQ_DEV_THRESH) begin
                // Count consecutive violations
                if (viol_cnt < VIOL_THRESH)
                    viol_cnt <= viol_cnt + 4'd1;
                else
                    freq_drift <= 1'b1;
            end
            else begin
                // Reset on clean cycle
                viol_cnt   <= 4'h0;
                freq_drift <= 1'b0;
            end
        end
    end

// ============================================================
// Combined Timing Anomaly Flag
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            timing_anomaly <= 1'b0;
        else
            timing_anomaly <= clk_glitch | freq_drift;
    end

// ============================================================
// Severity Classifier
// 00 = No threat
// 01 = Low    (freq drift only)
// 10 = Medium (clock glitch)
// 11 = High   (glitch + drift together)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            severity <= 2'b00;
        end
        else begin
            casex ({clk_glitch, freq_drift})
                2'b00 : severity <= 2'b00;
                2'b01 : severity <= 2'b01;
                2'b10 : severity <= 2'b10;
                2'b11 : severity <= 2'b11;
                default: severity <= 2'b00;
            endcase
        end
    end

endmodule


