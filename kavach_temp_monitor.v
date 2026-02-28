
`timescale 1ns / 1ps

module kavach_temp_monitor #(
    // ADC width for temperature sensor samples
    parameter ADC_WIDTH       = 12,

    // EWMA shift factor: alpha = 1/2^EWMA_SHIFT
    parameter EWMA_SHIFT      = 4,

    // Default deviation thresholds (in ADC counts)
    // Typical mapping: 1 ADC count ~ 0.1 deg C
    parameter TEMP_HI_THRESH  = 12'd150,   // +15 deg C spike
    parameter TEMP_LO_THRESH  = 12'd100,   // -10 deg C sudden drop

    // Sustained anomaly window (samples)
    parameter SUSTAIN_WIN     = 8'd6,

    // Rate-of-change threshold per sample
    parameter ROC_THRESH      = 12'd40,

    // Accumulator width
    parameter ACCUM_WIDTH     = ADC_WIDTH + EWMA_SHIFT
)(
    // ── Clock & Reset ────────────────────────────────────────
    input  wire                  clk,
    input  wire                  rst_n,

    // ── Sensor Input ──────────────────────────────────────────
    // Connect to on-chip thermal diode ADC output
    input  wire [ADC_WIDTH-1:0]  temp_sample,   // Raw ADC temp value
    input  wire                  sample_valid,   // New sample strobe

    // ── Runtime Config ────────────────────────────────────────
    input  wire [ADC_WIDTH-1:0]  hi_thresh_cfg,  // Override high threshold
    input  wire [ADC_WIDTH-1:0]  lo_thresh_cfg,  // Override low threshold
    input  wire                  use_cfg_thresh,  // 1 = use above

    // ── Outputs to Threat Classifier ──────────────────────────
    output reg                   temp_hi_anomaly, // Sudden temp spike
    output reg                   temp_lo_anomaly, // Sudden temp drop
    output reg                   temp_roc_alert,  // Rate-of-change alert
    output reg                   temp_sustained,  // Sustained deviation
    output reg  [ADC_WIDTH-1:0]  temp_baseline,   // EWMA baseline
    output reg  [ADC_WIDTH-1:0]  temp_delta,      // |sample - baseline|
    output reg  [ADC_WIDTH-1:0]  temp_roc,        // Rate of change
    output reg  [1:0]            severity,        // 00=none to 11=high
    output reg                   monitor_ready
);

// ============================================================
// Internal Signals
// ============================================================

    // EWMA accumulator
    reg  [ACCUM_WIDTH-1:0]  temp_accum;

    // Previous sample for rate-of-change
    reg  [ADC_WIDTH-1:0]    temp_prev;

    // Absolute delta (combinational)
    wire [ADC_WIDTH-1:0]    t_delta_w;

    // Rate of change (combinational)
    wire [ADC_WIDTH-1:0]    t_roc_w;

    // Active thresholds
    wire [ADC_WIDTH-1:0]    hi_thresh_act;
    wire [ADC_WIDTH-1:0]    lo_thresh_act;

    // Sustained anomaly counter
    reg  [7:0]              sustain_cnt;

    // Warmup counter
    reg  [7:0]              init_cnt;
    localparam              INIT_SAMPLES = 8'd24;

// ============================================================
// Threshold Mux
// ============================================================

    assign hi_thresh_act = use_cfg_thresh ? hi_thresh_cfg : TEMP_HI_THRESH;
    assign lo_thresh_act = use_cfg_thresh ? lo_thresh_cfg : TEMP_LO_THRESH;

// ============================================================
// Absolute Delta from Baseline (combinational)
// ============================================================

    assign t_delta_w = (temp_sample >= temp_baseline)
                       ? (temp_sample - temp_baseline)
                       : (temp_baseline - temp_sample);

// ============================================================
// Rate of Change - sample-to-sample (combinational)
// ============================================================

    assign t_roc_w = (temp_sample >= temp_prev)
                     ? (temp_sample - temp_prev)
                     : (temp_prev - temp_sample);

// ============================================================
// EWMA Baseline Update
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            temp_accum    <= {ACCUM_WIDTH{1'b0}};
            temp_baseline <= {ADC_WIDTH{1'b0}};
            temp_delta    <= {ADC_WIDTH{1'b0}};
            temp_prev     <= {ADC_WIDTH{1'b0}};
            temp_roc      <= {ADC_WIDTH{1'b0}};
            init_cnt      <= 8'h00;
            monitor_ready <= 1'b0;
        end
       else if (sample_valid) begin
    // EWMA accumulator update
    // FREEZE baseline on sudden thermal spike
    if (t_roc_w > ROC_THRESH) begin
        temp_accum <= temp_accum;   // hold
    end else begin
        temp_accum <= temp_accum
                      - (temp_accum >> EWMA_SHIFT)
                      + {{EWMA_SHIFT{1'b0}}, temp_sample};
    end

            // Baseline extract
            temp_baseline <= temp_accum[ACCUM_WIDTH-1:EWMA_SHIFT];

            // Capture outputs
            temp_delta <= t_delta_w;
            temp_roc   <= t_roc_w;
            temp_prev  <= temp_sample;

            // Warmup
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
// High / Low Spike Anomaly Detection
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            temp_hi_anomaly <= 1'b0;
            temp_lo_anomaly <= 1'b0;
        end
        else if (sample_valid && monitor_ready) begin
            // High spike: sample >> baseline (laser heating)
            temp_hi_anomaly <= (temp_sample > temp_baseline) &&
                               (t_delta_w  > hi_thresh_act);

            // Low drop: sample << baseline (cryo attack)
            temp_lo_anomaly <= (temp_sample < temp_baseline) &&
                               (t_delta_w  > lo_thresh_act);
        end
    end

// ============================================================
// Rate-of-Change Alert
// Flags rapid thermal change even before baseline diverges
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            temp_roc_alert <= 1'b0;
        end
        else if (sample_valid && monitor_ready) begin
            temp_roc_alert <= (t_roc_w > ROC_THRESH) ? 1'b1 : 1'b0;
        end
    end

// ============================================================
// Sustained Deviation Detector
// Flags if anomaly persists for SUSTAIN_WIN consecutive samples
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            sustain_cnt    <= 8'h00;
            temp_sustained <= 1'b0;
        end
        else if (sample_valid && monitor_ready) begin
            if (t_delta_w > (hi_thresh_act >> 1)) begin
                // Anomaly persisting
                if (sustain_cnt < SUSTAIN_WIN)
                    sustain_cnt <= sustain_cnt + 8'd1;
                else
                    temp_sustained <= 1'b1;
            end
            else begin
                // Clean sample - reset
                sustain_cnt    <= 8'h00;
                temp_sustained <= 1'b0;
            end
        end
    end

// ============================================================
// Severity Classifier
// 00 = No threat
// 01 = Low    (RoC alert only)
// 10 = Medium (hi or lo spike)
// 11 = High   (sustained + spike or RoC)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            severity <= 2'b00;
        end
        else begin
            if (temp_sustained && (temp_hi_anomaly || temp_lo_anomaly))
                severity <= 2'b11;
            else if (temp_hi_anomaly || temp_lo_anomaly)
                severity <= 2'b10;
            else if (temp_roc_alert)
                severity <= 2'b10;
            else
                severity <= 2'b00;
        end
    end

endmodule
