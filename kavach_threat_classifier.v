
`timescale 1ns / 1ps

module kavach_threat_classifier #(
    // Score width from EWMA engine
    parameter SCORE_WIDTH       = 8,

    // Threat level encoding
    parameter THREAT_NONE       = 3'd0,
    parameter THREAT_LOW        = 3'd1,
    parameter THREAT_MEDIUM     = 3'd2,
    parameter THREAT_HIGH       = 3'd3,
    parameter THREAT_CRITICAL   = 3'd4,

    // Fused score thresholds for threat levels
    parameter SCORE_LOW         = 8'd20,
    parameter SCORE_MEDIUM      = 8'd60,
    parameter SCORE_HIGH        = 8'd120,
    parameter SCORE_CRITICAL    = 8'd200,

    // Hysteresis: threat level holds for N cycles before downgrade
    parameter HYSTERESIS_WIN    = 8'd16,

    // Consecutive confirmations before upgrading threat level
    parameter CONFIRM_WIN       = 4'd3,

    // Attack type encoding width
    parameter ATTACK_TYPE_WIDTH = 4
)(
    // ── Clock & Reset ────────────────────────────────────────
    input  wire                       clk,
    input  wire                       rst_n,

    // ── Domain Monitor Flags ──────────────────────────────────
    input  wire                       volt_anomaly,
    input  wire                       curr_anomaly,
    input  wire                       glitch_detected,
    input  wire                       clk_glitch,
    input  wire                       freq_drift,
    input  wire                       temp_hi_anomaly,
    input  wire                       temp_lo_anomaly,
    input  wire                       temp_roc_alert,
    input  wire                       ipc_anomaly,
    input  wire                       pc_jump_anomaly,
    input  wire                       priv_anomaly,
    input  wire                       mem_oob_anomaly,
    input  wire                       flush_anomaly,
    input  wire                       nmi_anomaly,

    // ── Domain Severity Inputs ────────────────────────────────
    input  wire [1:0]                 sev_power,
    input  wire [1:0]                 sev_timing,
    input  wire [1:0]                 sev_temp,
    input  wire [1:0]                 sev_exec,

    // ── EWMA Engine Fusion Inputs ─────────────────────────────
    input  wire [SCORE_WIDTH-1:0]     fused_score,
    input  wire [1:0]                 fused_severity,
    input  wire                       multi_domain_alert,
    input  wire                       correlated_attack,
    input  wire                       engine_ready,

    // ── Outputs to Response Controller ───────────────────────
    output reg  [2:0]                 threat_level,     // NONE to CRITICAL
    output reg  [ATTACK_TYPE_WIDTH-1:0] attack_type,   // Attack classification
    output reg  [SCORE_WIDTH-1:0]     threat_score,    // Raw score forwarded
    output reg                        threat_valid,    // New threat event
    output reg                        threat_upgraded, // Level went up
    output reg                        threat_cleared,  // Level went to NONE

    // ── Attack Type Flags (individual) ───────────────────────
    output reg                        is_power_glitch,
    output reg                        is_clock_attack,
    output reg                        is_thermal_attack,
    output reg                        is_fault_injection,
    output reg                        is_side_channel,
    output reg                        is_combined_attack,

    // ── Classifier Status ─────────────────────────────────────
    output reg  [2:0]                 prev_threat_level,
    output reg  [7:0]                 hysteresis_cnt,
    output reg                        classifier_ready
);

// ============================================================
// Attack Type Encoding
// 4-bit encoded attack classification
// ============================================================
// 0000 = None
// 0001 = Power Glitch
// 0010 = Clock Attack
// 0011 = Thermal Attack
// 0100 = Fault Injection (execution-level)
// 0101 = Side Channel
// 0110 = Combined / Coordinated Attack
// 0111 = Unknown / Unclassified

    localparam AT_NONE       = 4'h0;
    localparam AT_PWR_GLITCH = 4'h1;
    localparam AT_CLK_ATTACK = 4'h2;
    localparam AT_THERMAL    = 4'h3;
    localparam AT_FAULT_INJ  = 4'h4;
    localparam AT_SIDE_CH    = 4'h5;
    localparam AT_COMBINED   = 4'h6;
    localparam AT_UNKNOWN    = 4'h7;

// ============================================================
// FSM State Encoding
// ============================================================

    localparam ST_IDLE      = 3'd0; // No threat
    localparam ST_LOW       = 3'd1; // Low threat - log only
    localparam ST_MEDIUM    = 3'd2; // Medium - alert issued
    localparam ST_HIGH      = 3'd3; // High - partial isolation
    localparam ST_CRITICAL  = 3'd4; // Critical - full isolation
    localparam ST_HYSTER    = 3'd5; // Hysteresis hold before downgrade

    reg [2:0] state, next_state;

// ============================================================
// Internal Signals
// ============================================================

    // Confirmation counter (avoid false positives)
    reg [3:0]  confirm_cnt;

    // Combined raw anomaly flag
    wire       any_anomaly;
    assign any_anomaly = volt_anomaly    | curr_anomaly    |
                         glitch_detected | clk_glitch      |
                         freq_drift      | temp_hi_anomaly |
                         temp_lo_anomaly | temp_roc_alert  |
                         ipc_anomaly     | pc_jump_anomaly |
                         priv_anomaly    | mem_oob_anomaly |
                         flush_anomaly   | nmi_anomaly;

    // Weighted score (internal)
    reg [SCORE_WIDTH-1:0] weighted_score;

    // Previous state for transition detection
    reg [2:0] state_prev;

    // Warmup
    reg [7:0] init_cnt;
    localparam INIT_CYCLES = 8'd32;

// ============================================================
// Weighted Score Computation
// Priority weights: Critical flags carry higher weight
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            weighted_score <= 8'h00;
        end
        else begin
            weighted_score <=
                // Base fused score from EWMA engine
                fused_score

                // Critical individual flags - high weight
                + (priv_anomaly    ? 8'd40 : 8'd0)
                + (correlated_attack ? 8'd35 : 8'd0)
                + (glitch_detected ? 8'd30 : 8'd0)
                + (clk_glitch      ? 8'd25 : 8'd0)

                // Medium weight flags
                + (pc_jump_anomaly ? 8'd20 : 8'd0)
                + (mem_oob_anomaly ? 8'd20 : 8'd0)
                + (nmi_anomaly     ? 8'd15 : 8'd0)
                + (multi_domain_alert ? 8'd15 : 8'd0)

                // Low weight flags
                + (volt_anomaly    ? 8'd10 : 8'd0)
                + (curr_anomaly    ? 8'd10 : 8'd0)
                + (temp_hi_anomaly ? 8'd10 : 8'd0)
                + (temp_lo_anomaly ? 8'd10 : 8'd0)
                + (freq_drift      ? 8'd8  : 8'd0)
                + (ipc_anomaly     ? 8'd8  : 8'd0)
                + (flush_anomaly   ? 8'd5  : 8'd0)
                + (temp_roc_alert  ? 8'd5  : 8'd0);
        end
    end

// ============================================================
// Attack Type Classifier
// Determines the nature of the attack based on flag patterns
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            attack_type       <= AT_NONE;
            is_power_glitch   <= 1'b0;
            is_clock_attack   <= 1'b0;
            is_thermal_attack <= 1'b0;
            is_fault_injection<= 1'b0;
            is_side_channel   <= 1'b0;
            is_combined_attack<= 1'b0;
        end
        else begin
            // Combined / Coordinated attack - highest priority
            if (correlated_attack || multi_domain_alert) begin
                attack_type        <= AT_COMBINED;
                is_combined_attack <= 1'b1;
                is_power_glitch    <= volt_anomaly | glitch_detected;
                is_clock_attack    <= clk_glitch   | freq_drift;
                is_thermal_attack  <= temp_hi_anomaly | temp_lo_anomaly;
                is_fault_injection <= pc_jump_anomaly | priv_anomaly;
                is_side_channel    <= ipc_anomaly;
            end
            // Privilege escalation + PC jump = Fault Injection
            else if (priv_anomaly || pc_jump_anomaly) begin
                attack_type        <= AT_FAULT_INJ;
                is_fault_injection <= 1'b1;
                is_combined_attack <= 1'b0;
                is_power_glitch    <= 1'b0;
                is_clock_attack    <= 1'b0;
                is_thermal_attack  <= 1'b0;
                is_side_channel    <= 1'b0;
            end
            // Power glitch attack
            else if (glitch_detected || (volt_anomaly && curr_anomaly)) begin
                attack_type        <= AT_PWR_GLITCH;
                is_power_glitch    <= 1'b1;
                is_fault_injection <= 1'b0;
                is_combined_attack <= 1'b0;
                is_clock_attack    <= 1'b0;
                is_thermal_attack  <= 1'b0;
                is_side_channel    <= 1'b0;
            end
            // Clock manipulation attack
            else if (clk_glitch || freq_drift) begin
                attack_type        <= AT_CLK_ATTACK;
                is_clock_attack    <= 1'b1;
                is_power_glitch    <= 1'b0;
                is_fault_injection <= 1'b0;
                is_combined_attack <= 1'b0;
                is_thermal_attack  <= 1'b0;
                is_side_channel    <= 1'b0;
            end
            // Thermal attack (laser or cryo)
            else if (temp_hi_anomaly || temp_lo_anomaly) begin
                attack_type        <= AT_THERMAL;
                is_thermal_attack  <= 1'b1;
                is_power_glitch    <= 1'b0;
                is_clock_attack    <= 1'b0;
                is_fault_injection <= 1'b0;
                is_combined_attack <= 1'b0;
                is_side_channel    <= 1'b0;
            end
            // Side channel (IPC anomaly only)
            else if (ipc_anomaly) begin
                attack_type        <= AT_SIDE_CH;
                is_side_channel    <= 1'b1;
                is_power_glitch    <= 1'b0;
                is_clock_attack    <= 1'b0;
                is_thermal_attack  <= 1'b0;
                is_fault_injection <= 1'b0;
                is_combined_attack <= 1'b0;
            end
            // No threat
            else begin
                attack_type        <= AT_NONE;
                is_power_glitch    <= 1'b0;
                is_clock_attack    <= 1'b0;
                is_thermal_attack  <= 1'b0;
                is_fault_injection <= 1'b0;
                is_side_channel    <= 1'b0;
                is_combined_attack <= 1'b0;
            end
        end
    end

// ============================================================
// Threat Level FSM - Sequential (state register)
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= ST_IDLE;
            state_prev <= ST_IDLE;
        end
        else begin
            state_prev <= state;
            state      <= next_state;
        end
    end

// ============================================================
// Threat Level FSM - Combinational (next state logic)
// ============================================================

    always @(*) begin
        next_state = state; // Default: hold state

        case (state)
            ST_IDLE: begin
                // engine_ready gate removed - classifier acts on any_anomaly
                // even during warmup to ensure no attack is missed
                if (weighted_score >= SCORE_CRITICAL || priv_anomaly)
                    next_state = ST_CRITICAL;
                else if (weighted_score >= SCORE_HIGH)
                    next_state = ST_HIGH;
                else if (weighted_score >= SCORE_MEDIUM)
                    next_state = ST_MEDIUM;
                else if (weighted_score >= SCORE_LOW)
                    next_state = ST_LOW;
                else
                    next_state = ST_IDLE;
            end

            ST_LOW: begin
                if (weighted_score >= SCORE_CRITICAL)
                    next_state = ST_CRITICAL;
                else if (weighted_score >= SCORE_HIGH)
                    next_state = ST_HIGH;
                else if (weighted_score >= SCORE_MEDIUM)
                    next_state = ST_MEDIUM;
                else if (weighted_score < SCORE_LOW)
                    next_state = ST_HYSTER;
                else
                    next_state = ST_LOW;
            end

            ST_MEDIUM: begin
                if (weighted_score >= SCORE_CRITICAL)
                    next_state = ST_CRITICAL;
                else if (weighted_score >= SCORE_HIGH)
                    next_state = ST_HIGH;
                else if (weighted_score < SCORE_MEDIUM)
                    next_state = ST_HYSTER;
                else
                    next_state = ST_MEDIUM;
            end

            ST_HIGH: begin
                if (weighted_score >= SCORE_CRITICAL || correlated_attack)
                    next_state = ST_CRITICAL;
                else if (weighted_score < SCORE_HIGH)
                    next_state = ST_HYSTER;
                else
                    next_state = ST_HIGH;
            end

            ST_CRITICAL: begin
                // Only downgrade after hysteresis
                if (weighted_score < SCORE_HIGH && !any_anomaly)
                    next_state = ST_HYSTER;
                else
                    next_state = ST_CRITICAL;
            end

            ST_HYSTER: begin
                // Hold current level - downgrade after timeout
                if (weighted_score >= SCORE_CRITICAL)
                    next_state = ST_CRITICAL;
                else if (weighted_score >= SCORE_HIGH)
                    next_state = ST_HIGH;
                else if (hysteresis_cnt >= HYSTERESIS_WIN)
                    next_state = ST_IDLE;
                else
                    next_state = ST_HYSTER;
            end

            default: next_state = ST_IDLE;
        endcase
    end

// ============================================================
// Hysteresis Counter
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            hysteresis_cnt <= 8'h00;
        else if (state == ST_HYSTER)
            hysteresis_cnt <= hysteresis_cnt + 8'd1;
        else
            hysteresis_cnt <= 8'h00;
    end

// ============================================================
// Output Register - Threat Level + Transition Flags
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            threat_level      <= THREAT_NONE;
            prev_threat_level <= THREAT_NONE;
            threat_score      <= 8'h00;
            threat_valid      <= 1'b0;
            threat_upgraded   <= 1'b0;
            threat_cleared    <= 1'b0;
            classifier_ready  <= 1'b0;
        end
        else begin
            // classifier_ready asserted immediately - no warmup gate
            classifier_ready  <= 1'b1;

            prev_threat_level <= threat_level;
            threat_score      <= weighted_score;

            // Map FSM state to threat level output
            case (state)
                ST_IDLE    : threat_level <= THREAT_NONE;
                ST_LOW     : threat_level <= THREAT_LOW;
                ST_MEDIUM  : threat_level <= THREAT_MEDIUM;
                ST_HIGH    : threat_level <= THREAT_HIGH;
                ST_CRITICAL: threat_level <= THREAT_CRITICAL;
                ST_HYSTER  : threat_level <= prev_threat_level; // Hold
                default    : threat_level <= THREAT_NONE;
            endcase

            // Transition flags
            threat_valid    <= (state != ST_IDLE) && (state != ST_HYSTER);
            threat_upgraded <= (state > state_prev);
            threat_cleared  <= (state == ST_IDLE) && (state_prev != ST_IDLE);
        end
    end

endmodule

// ============================================================
// END OF FILE: kavach_threat_classifier.v
// KAVACH IP - Module 6 of 10
// Next: kavach_response_controller.v (Module 7)
// ============================================================
