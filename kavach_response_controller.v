
`timescale 1ns / 1ps

module kavach_response_controller #(
    // Threat level encoding (must match classifier)
    parameter THREAT_NONE     = 3'd0,
    parameter THREAT_LOW      = 3'd1,
    parameter THREAT_MEDIUM   = 3'd2,
    parameter THREAT_HIGH     = 3'd3,
    parameter THREAT_CRITICAL = 3'd4,

    // Attack type width
    parameter ATTACK_TYPE_WIDTH = 4,

    // Score width
    parameter SCORE_WIDTH     = 8,

    // Watchdog timeout (cycles) before forcing safe state
    parameter WDT_TIMEOUT     = 32'd1000,

    // Response hold cycles before allowing downgrade
    parameter RESP_HOLD_WIN   = 16'd64,

    // Number of controllable modules (isolation targets)
    parameter NUM_MODULES     = 8
)(
    // ── Clock & Reset ────────────────────────────────────────
    input  wire                        clk,
    input  wire                        rst_n,

    // ── Threat Classifier Inputs ──────────────────────────────
    input  wire [2:0]                  threat_level,
    input  wire [ATTACK_TYPE_WIDTH-1:0] attack_type,
    input  wire [SCORE_WIDTH-1:0]      threat_score,
    input  wire                        threat_valid,
    input  wire                        threat_upgraded,
    input  wire                        threat_cleared,

    // ── Attack Type Flags ─────────────────────────────────────
    input  wire                        is_power_glitch,
    input  wire                        is_clock_attack,
    input  wire                        is_thermal_attack,
    input  wire                        is_fault_injection,
    input  wire                        is_side_channel,
    input  wire                        is_combined_attack,

    // ── Forensic & Recovery Handshake ─────────────────────────
    input  wire                        forensic_captured, // Module 8 done
    input  wire                        recovery_done,     // Module 9 done
    input  wire                        recovery_ready,    // Module 9 ready

    // ── Runtime Config ────────────────────────────────────────
    input  wire [NUM_MODULES-1:0]      module_isolate_mask, // Which modules to isolate
    input  wire                        override_enable,     // Manual override
    input  wire [2:0]                  override_level,      // Forced response level

    // ── Response Output Signals ───────────────────────────────
    // Level 1 - Logging
    output reg                         log_event,          // Trigger forensic log
    output reg  [SCORE_WIDTH-1:0]      log_score,          // Score to log
    output reg  [ATTACK_TYPE_WIDTH-1:0] log_attack_type,   // Type to log

    // Level 2 - Alert
    output reg                         alert_irq,          // Alert interrupt to CPU
    output reg                         alert_gpio,         // External GPIO alert pin

    // Level 3 - Throttle
    output reg                         clk_throttle_en,    // Reduce clock frequency
    output reg  [3:0]                  clk_div_factor,     // Clock division factor

    // Level 4 - Partial Isolation
    output reg  [NUM_MODULES-1:0]      module_isolate,     // Per-module isolation
    output reg                         bus_isolate,        // Isolate system bus
    output reg                         dma_halt,           // Halt DMA engines

    // Level 5 - Full Isolation / Lockdown
    output reg                         sys_lockdown,       // Full system lockdown
    output reg                         crypto_zeroize,     // Zeroize crypto keys
    output reg                         puf_lock,           // Lock PUF access
    output reg                         debug_disable,      // Disable JTAG/debug
    output reg                         watchdog_kick,      // Kick external WDT

    // ── Recovery Control ──────────────────────────────────────
    output reg                         recovery_trigger,   // Start recovery FSM
    output reg                         forensic_trigger,   // Start forensic capture

    // ── Status Outputs ────────────────────────────────────────
    output reg  [2:0]                  active_response,    // Current response level
    output reg  [2:0]                  prev_response,      // Previous response level
    output reg                         response_stable,    // Response not changing
    output reg  [15:0]                 resp_hold_cnt,      // Hold counter value
    output reg                         controller_ready
);

// ============================================================
// FSM State Encoding
// ============================================================

    localparam RSP_IDLE      = 3'd0; // No response - monitoring
    localparam RSP_LOG       = 3'd1; // Level 1: Log event only
    localparam RSP_ALERT     = 3'd2; // Level 2: Alert + log
    localparam RSP_THROTTLE  = 3'd3; // Level 3: Throttle + alert
    localparam RSP_ISOLATE   = 3'd4; // Level 4: Partial isolation
    localparam RSP_LOCKDOWN  = 3'd5; // Level 5: Full lockdown
    localparam RSP_RECOVER   = 3'd6; // Recovery state
    localparam RSP_HOLD      = 3'd7; // Hold before downgrade

    reg [2:0] rsp_state, rsp_next;

// ============================================================
// Internal Signals
// ============================================================

    // Active threat level (override mux)
    wire [2:0] active_threat;
    assign active_threat = override_enable ? override_level : threat_level;

    // Watchdog counter
    reg [31:0] wdt_cnt;
    wire       wdt_expired;
    assign wdt_expired = (wdt_cnt >= WDT_TIMEOUT);

    // Response hold counter
    reg [15:0] hold_cnt;

    // Warmup
    reg [7:0]  init_cnt;
    localparam INIT_CYCLES = 8'd16;

    // State previous
    reg [2:0]  rsp_state_prev;

// ============================================================
// FSM - Sequential
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rsp_state      <= RSP_IDLE;
            rsp_state_prev <= RSP_IDLE;
        end
        else begin
            rsp_state_prev <= rsp_state;
            rsp_state      <= rsp_next;
        end
    end

// ============================================================
// FSM - Combinational Next State
// ============================================================

    always @(*) begin
        rsp_next = rsp_state; // Default hold

        case (rsp_state)

            RSP_IDLE: begin
                if (!controller_ready)
                    rsp_next = RSP_IDLE;
                else if (wdt_expired)
                    rsp_next = RSP_LOCKDOWN;
                else begin
                    case (active_threat)
                        THREAT_NONE    : rsp_next = RSP_IDLE;
                        THREAT_LOW     : rsp_next = RSP_LOG;
                        THREAT_MEDIUM  : rsp_next = RSP_ALERT;
                        THREAT_HIGH    : rsp_next = RSP_THROTTLE;
                        THREAT_CRITICAL: rsp_next = RSP_LOCKDOWN;
                        default        : rsp_next = RSP_IDLE;
                    endcase
                end
            end

            RSP_LOG: begin
                if (wdt_expired)
                    rsp_next = RSP_LOCKDOWN;
                else if (active_threat >= THREAT_MEDIUM)
                    rsp_next = RSP_ALERT;
                else if (active_threat == THREAT_NONE)
                    rsp_next = RSP_HOLD;
                else
                    rsp_next = RSP_LOG;
            end

            RSP_ALERT: begin
                if (wdt_expired)
                    rsp_next = RSP_LOCKDOWN;
                else if (active_threat >= THREAT_HIGH)
                    rsp_next = RSP_THROTTLE;
                else if (active_threat <= THREAT_LOW)
                    rsp_next = RSP_HOLD;
                else
                    rsp_next = RSP_ALERT;
            end

            RSP_THROTTLE: begin
                if (wdt_expired || active_threat == THREAT_CRITICAL)
                    rsp_next = RSP_LOCKDOWN;
                else if (active_threat == THREAT_HIGH)
                    rsp_next = RSP_ISOLATE;
                else if (active_threat <= THREAT_MEDIUM)
                    rsp_next = RSP_HOLD;
                else
                    rsp_next = RSP_THROTTLE;
            end

            RSP_ISOLATE: begin
                if (wdt_expired || active_threat == THREAT_CRITICAL
                    || is_combined_attack)
                    rsp_next = RSP_LOCKDOWN;
                else if (active_threat < THREAT_HIGH)
                    rsp_next = RSP_HOLD;
                else
                    rsp_next = RSP_ISOLATE;
            end

            RSP_LOCKDOWN: begin
                // Stay locked until forensic done + recovery ready
                if (forensic_captured && recovery_ready)
                    rsp_next = RSP_RECOVER;
                else
                    rsp_next = RSP_LOCKDOWN;
            end

            RSP_RECOVER: begin
                if (recovery_done)
                    rsp_next = RSP_IDLE;
                else
                    rsp_next = RSP_RECOVER;
            end

            RSP_HOLD: begin
                if (wdt_expired)
                    rsp_next = RSP_LOCKDOWN;
                else if (active_threat >= THREAT_HIGH)
                    rsp_next = RSP_ISOLATE;
                else if (hold_cnt >= RESP_HOLD_WIN)
                    rsp_next = RSP_IDLE;
                else
                    rsp_next = RSP_HOLD;
            end

            default: rsp_next = RSP_IDLE;
        endcase
    end

// ============================================================
// Hold Counter
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            hold_cnt <= 16'h0000;
        else if (rsp_state == RSP_HOLD)
            hold_cnt <= hold_cnt + 16'd1;
        else
            hold_cnt <= 16'h0000;
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            resp_hold_cnt <= 16'h0000;
        else
            resp_hold_cnt <= hold_cnt;
    end

// ============================================================
// Watchdog Counter
// Resets on any valid threat event - expires if stuck
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            wdt_cnt <= 32'h0000_0000;
        else if (threat_valid || rsp_state == RSP_IDLE)
            wdt_cnt <= 32'h0000_0000;
        else
            wdt_cnt <= wdt_cnt + 32'd1;
    end

// ============================================================
// Output Register - Response Actions per FSM State
// ============================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // Clear all response outputs
            log_event        <= 1'b0;
            log_score        <= 8'h00;
            log_attack_type  <= 4'h0;
            alert_irq        <= 1'b0;
            alert_gpio       <= 1'b0;
            clk_throttle_en  <= 1'b0;
            clk_div_factor   <= 4'h1;
            module_isolate   <= {NUM_MODULES{1'b0}};
            bus_isolate      <= 1'b0;
            dma_halt         <= 1'b0;
            sys_lockdown     <= 1'b0;
            crypto_zeroize   <= 1'b0;
            puf_lock         <= 1'b0;
            debug_disable    <= 1'b0;
            watchdog_kick    <= 1'b0;
            recovery_trigger <= 1'b0;
            forensic_trigger <= 1'b0;
            active_response  <= 3'd0;
            prev_response    <= 3'd0;
            response_stable  <= 1'b0;
            init_cnt         <= 8'h00;
            controller_ready <= 1'b0;
        end
        else begin
            // Warmup
            if (init_cnt < INIT_CYCLES) begin
                init_cnt         <= init_cnt + 8'd1;
                controller_ready <= 1'b0;
            end
            else
                controller_ready <= 1'b1;

            prev_response   <= active_response;
            active_response <= rsp_state;
            response_stable <= (rsp_state == rsp_state_prev);

            // Default deassert
            log_event        <= 1'b0;
            //alert_irq        <= 1'b0;
            // NEW
alert_irq <= (threat_valid && active_threat >= THREAT_MEDIUM);
            alert_gpio       <= 1'b0;
            clk_throttle_en  <= 1'b0;
            clk_div_factor   <= 4'h1;
            module_isolate   <= {NUM_MODULES{1'b0}};
            bus_isolate      <= 1'b0;
            dma_halt         <= 1'b0;
            sys_lockdown     <= 1'b0;
            crypto_zeroize   <= 1'b0;
            puf_lock         <= 1'b0;
            //debug_disable    <= 1'b0;
            // NEW
             debug_disable <= (is_fault_injection && threat_valid);
            watchdog_kick    <= 1'b1; // Always kick WDT when alive
            recovery_trigger <= 1'b0;
            forensic_trigger <= 1'b0;

            case (rsp_state)

                // ── Level 0: No threat ────────────────────────
                RSP_IDLE: begin
                    // All outputs deasserted (defaults above)
                end

                // ── Level 1: Log Event ────────────────────────
                RSP_LOG: begin
                    log_event       <= 1'b1;
                    log_score       <= threat_score;
                    log_attack_type <= attack_type;
                    forensic_trigger<= 1'b1;
                end

                // ── Level 2: Alert ────────────────────────────
                RSP_ALERT: begin
                    log_event       <= 1'b1;
                    log_score       <= threat_score;
                    log_attack_type <= attack_type;
                    forensic_trigger<= 1'b1;
                    alert_irq       <= 1'b1;
                    alert_gpio      <= 1'b1;
                end

                // ── Level 3: Throttle ─────────────────────────
                RSP_THROTTLE: begin
                    log_event       <= 1'b1;
                    log_score       <= threat_score;
                    log_attack_type <= attack_type;
                    forensic_trigger<= 1'b1;
                    alert_irq       <= 1'b1;
                    alert_gpio      <= 1'b1;
                    clk_throttle_en <= 1'b1;
                    // Clock attack = aggressive throttle
                    clk_div_factor  <= is_clock_attack ? 4'h8 : 4'h4;
                    dma_halt        <= 1'b1;
                end

                // ── Level 4: Partial Isolation ────────────────
                RSP_ISOLATE: begin
                    log_event       <= 1'b1;
                    log_score       <= threat_score;
                    log_attack_type <= attack_type;
                    forensic_trigger<= 1'b1;
                    alert_irq       <= 1'b1;
                    alert_gpio      <= 1'b1;
                    clk_throttle_en <= 1'b1;
                    clk_div_factor  <= 4'h8;
                    dma_halt        <= 1'b1;
                    bus_isolate     <= 1'b1;
                    debug_disable   <= 1'b1;
                    // Isolate only masked modules
                    module_isolate  <= module_isolate_mask;
                end

                // ── Level 5: Full Lockdown ────────────────────
                RSP_LOCKDOWN: begin
                    log_event        <= 1'b1;
                    log_score        <= threat_score;
                    log_attack_type  <= attack_type;
                    forensic_trigger <= 1'b1;
                    alert_irq        <= 1'b1;
                    alert_gpio       <= 1'b1;
                    clk_throttle_en  <= 1'b1;
                    clk_div_factor   <= 4'hF; // Max throttle
                    dma_halt         <= 1'b1;
                    bus_isolate      <= 1'b1;
                    debug_disable    <= 1'b1;
                    module_isolate   <= {NUM_MODULES{1'b1}}; // All modules
                    sys_lockdown     <= 1'b1;
                    crypto_zeroize   <= is_fault_injection | is_combined_attack;
                    puf_lock         <= 1'b1;
                    watchdog_kick    <= 1'b0; // Let WDT expire = hard reset
                end

                // ── Recovery ─────────────────────────────────
                RSP_RECOVER: begin
                    recovery_trigger <= 1'b1;
                    alert_irq        <= 1'b1;
                    debug_disable    <= 1'b1;
                    // Gradually release isolation during recovery
                    sys_lockdown     <= 1'b0;
                    puf_lock         <= 1'b0;
                end

                // ── Hold ──────────────────────────────────────
                RSP_HOLD: begin
                    log_event       <= 1'b1;
                    log_score       <= threat_score;
                    log_attack_type <= attack_type;
                    // Maintain reduced clock until clean
                    clk_throttle_en <= 1'b1;
                    clk_div_factor  <= 4'h2;
                end

                default: begin
                    // Safe defaults
                end
            endcase
        end
    end

endmodule


