// ============================================================
// KAVACH IP - Module 10: Top-Level Integration
// ALL 9 MODULES INSTANTIATED
// ============================================================

`timescale 1ns / 1ps

module kavach_top #(
    parameter ADC_WIDTH         = 12,
    parameter PC_WIDTH          = 32,
    parameter SCORE_WIDTH       = 8,
    parameter ATTACK_TYPE_WIDTH = 4,
    parameter NUM_MODULES       = 8,
    parameter TIMESTAMP_WIDTH   = 48,
    parameter LOG_DEPTH         = 8,
    parameter LOG_ADDR_WIDTH    = 3,
    parameter EWMA_SHIFT        = 4,
    parameter VOLT_THRESH       = 12'd200,
    parameter CURR_THRESH       = 12'd150,
    parameter TEMP_HI_THRESH    = 12'd150,
    parameter TEMP_LO_THRESH    = 12'd100,
    parameter ROC_THRESH        = 12'd40,
    parameter IPC_THRESH        = 16'd50,
    parameter PC_JUMP_THRESH    = 32'h0000_FFFF,
    parameter STEP_HOLD_CYCLES  = 32'd256,
    parameter MAX_RETRY         = 3'd3
)(
    input  wire                       clk,
    input  wire                       rst_n,

    input  wire [ADC_WIDTH-1:0]       vdd_sample,
    input  wire [ADC_WIDTH-1:0]       idd_sample,
    input  wire                       pwr_sample_valid,

    input  wire                       mon_clk,
    input  wire                       ref_pulse,
    input  wire                       ref_valid,

    input  wire [ADC_WIDTH-1:0]       temp_sample,
    input  wire                       temp_sample_valid,

    input  wire [PC_WIDTH-1:0]        pc_current,
    input  wire [PC_WIDTH-1:0]        pc_prev,
    input  wire                       instr_retired,
    input  wire                       instr_flushed,
    input  wire [1:0]                 priv_level,
    input  wire                       mem_access,
    input  wire [PC_WIDTH-1:0]        mem_addr,
    input  wire                       mem_write,
    input  wire                       exception_taken,
    input  wire                       nmi_taken,

    input  wire                       integ_check_done,
    input  wire                       integ_check_pass,
    input  wire [NUM_MODULES-1:0]     module_restore_ack,
    input  wire                       sys_stable,

    input  wire [LOG_ADDR_WIDTH-1:0]  forensic_read_slot,
    input  wire                       forensic_read_req,
    input  wire                       forensic_read_ack,

    input  wire [NUM_MODULES-1:0]     module_isolate_mask,
    input  wire                       override_enable,
    input  wire [2:0]                 override_level,
    input  wire [PC_WIDTH-1:0]        valid_pc_base,
    input  wire [PC_WIDTH-1:0]        valid_pc_top,
    input  wire                       use_pc_bounds,

    output wire                       alert_irq,
    output wire                       alert_gpio,
    output wire                       clk_throttle_en,
    output wire [3:0]                 clk_div_factor,
    output wire [NUM_MODULES-1:0]     module_isolate,
    output wire                       bus_isolate,
    output wire                       dma_halt,
    output wire                       sys_lockdown,
    output wire                       crypto_zeroize,
    output wire                       puf_lock,
    output wire                       debug_disable,

    output wire                       integ_check_req,
    output wire                       clk_restore,
    output wire [3:0]                 clk_div_recover,
    output wire [NUM_MODULES-1:0]     module_restore,
    output wire                       bus_restore,
    output wire                       dma_restore,

    output wire [TIMESTAMP_WIDTH-1:0] forensic_timestamp,
    output wire [2:0]                 forensic_threat_level,
    output wire [ATTACK_TYPE_WIDTH-1:0] forensic_attack_type,
    output wire [SCORE_WIDTH-1:0]     forensic_score,
    output wire [PC_WIDTH-1:0]        forensic_pc,
    output wire                       forensic_read_valid,

    output wire [2:0]                 threat_level,
    output wire [ATTACK_TYPE_WIDTH-1:0] attack_type,
    output wire [SCORE_WIDTH-1:0]     threat_score,
    output wire [1:0]                 fused_severity,
    output wire                       multi_domain_alert,
    output wire                       correlated_attack,
    output wire [3:0]                 recovery_state,
    output wire                       recovery_done,
    output wire                       recovery_failed,
    output wire                       permanent_lockdown,
    output wire                       kavach_ready
);

// ============================================================
// Internal Wires
// ============================================================

    wire w_pwr_ready, w_timing_ready, w_temp_ready, w_exec_ready;
    wire w_engine_ready, w_classifier_ready, w_resp_ready;
    wire w_forensic_ready, w_recovery_ready;

    // Power Monitor
    wire                 w_volt_anomaly, w_curr_anomaly, w_glitch_detected;
    wire [ADC_WIDTH-1:0] w_volt_baseline, w_curr_baseline;
    wire [ADC_WIDTH-1:0] w_volt_delta, w_curr_delta;
    wire [1:0]           w_sev_power;

    // Timing Monitor
    wire        w_clk_glitch, w_freq_drift, w_timing_anomaly;
    wire [15:0] w_measured_period, w_period_baseline, w_period_delta;
    wire [1:0]  w_sev_timing;

    // Temp Monitor
    wire                 w_temp_hi_anomaly, w_temp_lo_anomaly;
    wire                 w_temp_roc_alert, w_temp_sustained;
    wire [ADC_WIDTH-1:0] w_temp_baseline, w_temp_delta, w_temp_roc;
    wire [1:0]           w_sev_temp;

    // Execution Monitor
    wire                w_ipc_anomaly, w_pc_jump_anomaly, w_priv_anomaly;
    wire                w_mem_oob_anomaly, w_flush_anomaly, w_nmi_anomaly;
    wire                w_exec_anomaly;
    wire [15:0]         w_ipc_baseline, w_ipc_current;
    wire [PC_WIDTH-1:0] w_last_bad_pc;
    wire [1:0]          w_sev_exec;

    // EWMA Engine
    wire [SCORE_WIDTH-1:0] w_fused_score;
    wire [1:0]             w_fused_severity;
    wire                   w_multi_domain_alert, w_correlated_attack;
    wire [4:0]             w_channel_ready;
    wire [15:0] w_bl0,w_bl1,w_bl2,w_bl3,w_bl4;
    wire [15:0] w_dl0,w_dl1,w_dl2,w_dl3,w_dl4;
    wire [SCORE_WIDTH-1:0] w_sc0,w_sc1,w_sc2,w_sc3,w_sc4;

    // Classifier
    wire [2:0]               w_threat_level;
    wire [ATTACK_TYPE_WIDTH-1:0] w_attack_type;
    wire [SCORE_WIDTH-1:0]   w_threat_score;
    wire                     w_threat_valid, w_threat_upgraded, w_threat_cleared;
    wire                     w_is_pwr, w_is_clk, w_is_thm, w_is_fi, w_is_sc, w_is_comb;
    wire [2:0]               w_prev_threat;
    wire [7:0]               w_hyst_cnt;

    // Response Controller
    wire                     w_forensic_trigger, w_recovery_trigger;
    wire [2:0]               w_active_response;
    wire                     w_forensic_captured, w_recovery_done;
    wire                     w_log_event, w_resp_stable, w_wdt_kick;
    wire [SCORE_WIDTH-1:0]   w_log_score;
    wire [ATTACK_TYPE_WIDTH-1:0] w_log_atype;
    wire [15:0]              w_resp_hold;

    // Recovery FSM
    wire [2:0]  w_retry_cnt;
    wire [31:0] w_step_timer;
    wire        w_dbg_restore, w_puf_restore;

    // Forensic
    wire [LOG_ADDR_WIDTH-1:0] w_log_wp, w_log_rp;
    wire [LOG_ADDR_WIDTH:0]   w_log_cnt;
    wire                      w_log_full, w_log_empty;

// ============================================================
// READY + Passthrough
// ============================================================

    assign kavach_ready = w_pwr_ready & w_timing_ready & w_temp_ready &
                          w_exec_ready & w_engine_ready & w_classifier_ready &
                          w_resp_ready & w_forensic_ready & w_recovery_ready;

    assign threat_level       = w_threat_level;
    assign attack_type        = w_attack_type;
    assign threat_score       = w_threat_score;
    assign fused_severity     = w_fused_severity;
    assign multi_domain_alert = w_multi_domain_alert;
    assign correlated_attack  = w_correlated_attack;
    assign recovery_done      = w_recovery_done;

// ============================================================
// MODULE 1 - Power Monitor
// ============================================================

    kavach_power_monitor #(
        .ADC_WIDTH   (ADC_WIDTH),
        .EWMA_SHIFT  (EWMA_SHIFT),
        .VOLT_THRESH (VOLT_THRESH),
        .CURR_THRESH (CURR_THRESH)
    ) u_power_monitor (
        .clk             (clk),
        .rst_n           (rst_n),
        .vdd_sample      (vdd_sample),
        .idd_sample      (idd_sample),
        .sample_valid    (pwr_sample_valid),
        .volt_thresh_cfg ({ADC_WIDTH{1'b0}}),
        .curr_thresh_cfg ({ADC_WIDTH{1'b0}}),
        .use_cfg_thresh  (1'b0),
        .volt_anomaly    (w_volt_anomaly),
        .curr_anomaly    (w_curr_anomaly),
        .glitch_detected (w_glitch_detected),
        .volt_baseline   (w_volt_baseline),
        .curr_baseline   (w_curr_baseline),
        .volt_delta      (w_volt_delta),
        .curr_delta      (w_curr_delta),
        .severity        (w_sev_power),
        .monitor_ready   (w_pwr_ready)
    );

// ============================================================
// MODULE 2 - Timing Monitor
// ============================================================

    kavach_timing_monitor #(
        .EWMA_SHIFT  (EWMA_SHIFT)
    ) u_timing_monitor (
        .clk             (clk),
        .rst_n           (rst_n),
        .mon_clk         (mon_clk),
        .ref_pulse       (ref_pulse),
        .ref_valid       (ref_valid),
        .period_cfg      (16'h0000),
        .use_cfg         (1'b0),
        .clk_glitch      (w_clk_glitch),
        .freq_drift      (w_freq_drift),
        .timing_anomaly  (w_timing_anomaly),
        .measured_period (w_measured_period),
        .period_baseline (w_period_baseline),
        .period_delta    (w_period_delta),
        .severity        (w_sev_timing),
        .monitor_ready   (w_timing_ready)
    );

// ============================================================
// MODULE 3 - Temperature Monitor
// ============================================================

    kavach_temp_monitor #(
        .ADC_WIDTH      (ADC_WIDTH),
        .EWMA_SHIFT     (EWMA_SHIFT),
        .TEMP_HI_THRESH (TEMP_HI_THRESH),
        .TEMP_LO_THRESH (TEMP_LO_THRESH),
        .ROC_THRESH     (ROC_THRESH)
    ) u_temp_monitor (
        .clk             (clk),
        .rst_n           (rst_n),
        .temp_sample     (temp_sample),
        .sample_valid    (temp_sample_valid),
        .hi_thresh_cfg   ({ADC_WIDTH{1'b0}}),
        .lo_thresh_cfg   ({ADC_WIDTH{1'b0}}),
        .use_cfg_thresh  (1'b0),
        .temp_hi_anomaly (w_temp_hi_anomaly),
        .temp_lo_anomaly (w_temp_lo_anomaly),
        .temp_roc_alert  (w_temp_roc_alert),
        .temp_sustained  (w_temp_sustained),
        .temp_baseline   (w_temp_baseline),
        .temp_delta      (w_temp_delta),
        .temp_roc        (w_temp_roc),
        .severity        (w_sev_temp),
        .monitor_ready   (w_temp_ready)
    );

// ============================================================
// MODULE 4 - Execution Monitor
// ============================================================

    kavach_execution_monitor #(
        .PC_WIDTH       (PC_WIDTH),
        .EWMA_SHIFT     (EWMA_SHIFT),
        .IPC_THRESH     (IPC_THRESH),
        .PC_JUMP_THRESH (PC_JUMP_THRESH)
    ) u_exec_monitor (
        .clk             (clk),
        .rst_n           (rst_n),
        .pc_current      (pc_current),
        .pc_prev         (pc_prev),
        .instr_retired   (instr_retired),
        .instr_flushed   (instr_flushed),
        .priv_level      (priv_level),
        .mem_access      (mem_access),
        .mem_addr        (mem_addr),
        .mem_write       (mem_write),
        .exception_taken (exception_taken),
        .nmi_taken       (nmi_taken),
        .valid_pc_base   (valid_pc_base),
        .valid_pc_top    (valid_pc_top),
        .use_pc_bounds   (use_pc_bounds),
        .ipc_anomaly     (w_ipc_anomaly),
        .pc_jump_anomaly (w_pc_jump_anomaly),
        .priv_anomaly    (w_priv_anomaly),
        .mem_oob_anomaly (w_mem_oob_anomaly),
        .flush_anomaly   (w_flush_anomaly),
        .nmi_anomaly     (w_nmi_anomaly),
        .exec_anomaly    (w_exec_anomaly),
        .ipc_baseline    (w_ipc_baseline),
        .ipc_current     (w_ipc_current),
        .last_bad_pc     (w_last_bad_pc),
        .severity        (w_sev_exec),
        .monitor_ready   (w_exec_ready)
    );

// ============================================================
// MODULE 5 - EWMA Engine
// ============================================================

    kavach_ewma_engine #(
        .EWMA_SHIFT_DEF (EWMA_SHIFT),
        .SCORE_WIDTH    (SCORE_WIDTH)
    ) u_ewma_engine (
        .clk                (clk),
        .rst_n              (rst_n),
        .sample_ch0         ({{4{1'b0}}, w_volt_delta}),
        .sample_ch1         ({{4{1'b0}}, w_curr_delta}),
        .sample_ch2         (w_period_delta),
        .sample_ch3         ({{4{1'b0}}, w_temp_delta}),
        .sample_ch4         (w_ipc_current),
        .sample_valid       ({w_exec_ready, w_temp_ready,
                              w_timing_ready, w_pwr_ready,
                              w_pwr_ready}),
        .shift_cfg_ch0      (8'h04),
        .shift_cfg_ch1      (8'h04),
        .shift_cfg_ch2      (8'h04),
        .shift_cfg_ch3      (8'h04),
        .shift_cfg_ch4      (8'h04),
        .use_cfg_shift      (1'b0),
        .sev_power          (w_sev_power),
        .sev_timing         (w_sev_timing),
        .sev_temp           (w_sev_temp),
        .sev_exec           (w_sev_exec),
        .baseline_ch0       (w_bl0),
        .baseline_ch1       (w_bl1),
        .baseline_ch2       (w_bl2),
        .baseline_ch3       (w_bl3),
        .baseline_ch4       (w_bl4),
        .delta_ch0          (w_dl0),
        .delta_ch1          (w_dl1),
        .delta_ch2          (w_dl2),
        .delta_ch3          (w_dl3),
        .delta_ch4          (w_dl4),
        .score_ch0          (w_sc0),
        .score_ch1          (w_sc1),
        .score_ch2          (w_sc2),
        .score_ch3          (w_sc3),
        .score_ch4          (w_sc4),
        .fused_score        (w_fused_score),
        .fused_severity     (w_fused_severity),
        .multi_domain_alert (w_multi_domain_alert),
        .correlated_attack  (w_correlated_attack),
        .channel_ready      (w_channel_ready),
        .engine_ready       (w_engine_ready)
    );

// ============================================================
// MODULE 6 - Threat Classifier
// ============================================================

    kavach_threat_classifier #(
        .SCORE_WIDTH       (SCORE_WIDTH),
        .ATTACK_TYPE_WIDTH (ATTACK_TYPE_WIDTH)
    ) u_threat_classifier (
        .clk                (clk),
        .rst_n              (rst_n),
        .volt_anomaly       (w_volt_anomaly),
        .curr_anomaly       (w_curr_anomaly),
        .glitch_detected    (w_glitch_detected),
        .clk_glitch         (w_clk_glitch),
        .freq_drift         (w_freq_drift),
        .temp_hi_anomaly    (w_temp_hi_anomaly),
        .temp_lo_anomaly    (w_temp_lo_anomaly),
        .temp_roc_alert     (w_temp_roc_alert),
        .ipc_anomaly        (w_ipc_anomaly),
        .pc_jump_anomaly    (w_pc_jump_anomaly),
        .priv_anomaly       (w_priv_anomaly),
        .mem_oob_anomaly    (w_mem_oob_anomaly),
        .flush_anomaly      (w_flush_anomaly),
        .nmi_anomaly        (w_nmi_anomaly),
        .sev_power          (w_sev_power),
        .sev_timing         (w_sev_timing),
        .sev_temp           (w_sev_temp),
        .sev_exec           (w_sev_exec),
        .fused_score        (w_fused_score),
        .fused_severity     (w_fused_severity),
        .multi_domain_alert (w_multi_domain_alert),
        .correlated_attack  (w_correlated_attack),
        .engine_ready       (w_engine_ready),
        .threat_level       (w_threat_level),
        .attack_type        (w_attack_type),
        .threat_score       (w_threat_score),
        .threat_valid       (w_threat_valid),
        .threat_upgraded    (w_threat_upgraded),
        .threat_cleared     (w_threat_cleared),
        .is_power_glitch    (w_is_pwr),
        .is_clock_attack    (w_is_clk),
        .is_thermal_attack  (w_is_thm),
        .is_fault_injection (w_is_fi),
        .is_side_channel    (w_is_sc),
        .is_combined_attack (w_is_comb),
        .prev_threat_level  (w_prev_threat),
        .hysteresis_cnt     (w_hyst_cnt),
        .classifier_ready   (w_classifier_ready)
    );

// ============================================================
// MODULE 7 - Response Controller
// ============================================================

    kavach_response_controller #(
        .SCORE_WIDTH       (SCORE_WIDTH),
        .ATTACK_TYPE_WIDTH (ATTACK_TYPE_WIDTH),
        .NUM_MODULES       (NUM_MODULES)
    ) u_response_controller (
        .clk                (clk),
        .rst_n              (rst_n),
        .threat_level       (w_threat_level),
        .attack_type        (w_attack_type),
        .threat_score       (w_threat_score),
        .threat_valid       (w_threat_valid),
        .threat_upgraded    (w_threat_upgraded),
        .threat_cleared     (w_threat_cleared),
        .is_power_glitch    (w_is_pwr),
        .is_clock_attack    (w_is_clk),
        .is_thermal_attack  (w_is_thm),
        .is_fault_injection (w_is_fi),
        .is_side_channel    (w_is_sc),
        .is_combined_attack (w_is_comb),
        .forensic_captured  (w_forensic_captured),
        .recovery_done      (w_recovery_done),
        .recovery_ready     (w_recovery_ready),
        .module_isolate_mask(module_isolate_mask),
        .override_enable    (override_enable),
        .override_level     (override_level),
        .log_event          (w_log_event),
        .log_score          (w_log_score),
        .log_attack_type    (w_log_atype),
        .alert_irq          (alert_irq),
        .alert_gpio         (alert_gpio),
        .clk_throttle_en    (clk_throttle_en),
        .clk_div_factor     (clk_div_factor),
        .module_isolate     (module_isolate),
        .bus_isolate        (bus_isolate),
        .dma_halt           (dma_halt),
        .sys_lockdown       (sys_lockdown),
        .crypto_zeroize     (crypto_zeroize),
        .puf_lock           (puf_lock),
        .debug_disable      (debug_disable),
        .watchdog_kick      (w_wdt_kick),
        .recovery_trigger   (w_recovery_trigger),
        .forensic_trigger   (w_forensic_trigger),
        .active_response    (w_active_response),
        .prev_response      (),
        .response_stable    (w_resp_stable),
        .resp_hold_cnt      (w_resp_hold),
        .controller_ready   (w_resp_ready)
    );

// ============================================================
// MODULE 8 - Forensic Capture
// ============================================================

    kavach_forensic_capture #(
        .LOG_DEPTH         (LOG_DEPTH),
        .LOG_ADDR_WIDTH    (LOG_ADDR_WIDTH),
        .ADC_WIDTH         (ADC_WIDTH),
        .PC_WIDTH          (PC_WIDTH),
        .SCORE_WIDTH       (SCORE_WIDTH),
        .ATTACK_TYPE_WIDTH (ATTACK_TYPE_WIDTH),
        .TIMESTAMP_WIDTH   (TIMESTAMP_WIDTH)
    ) u_forensic_capture (
        .clk                (clk),
        .rst_n              (rst_n),
        .capture_trigger    (w_forensic_trigger),
        .threat_valid       (w_threat_valid),
        .threat_level       (w_threat_level),
        .attack_type        (w_attack_type),
        .threat_score       (w_threat_score),
        .response_taken     (w_active_response),
        .snap_vdd           (vdd_sample),
        .snap_idd           (idd_sample),
        .snap_temp          (temp_sample),
        .snap_period        (w_measured_period),
        .snap_ipc           (w_ipc_current),
        .base_vdd           (w_volt_baseline),
        .base_idd           (w_curr_baseline),
        .base_temp          (w_temp_baseline),
        .base_period        (w_period_baseline),
        .base_ipc           (w_ipc_baseline),
        .snap_pc            (pc_current),
        .snap_priv          (priv_level),
        .snap_bad_pc        (w_last_bad_pc),
        .delta_vdd          (w_volt_delta),
        .delta_temp         (w_temp_delta),
        .delta_period       (w_period_delta),
        .read_slot          (forensic_read_slot),
        .read_req           (forensic_read_req),
        .read_ack           (forensic_read_ack),
        .out_timestamp      (forensic_timestamp),
        .out_threat_level   (forensic_threat_level),
        .out_attack_type    (forensic_attack_type),
        .out_threat_score   (forensic_score),
        .out_response_taken (),
        .out_snap_vdd       (),
        .out_snap_idd       (),
        .out_snap_temp      (),
        .out_snap_period    (),
        .out_snap_ipc       (),
        .out_base_vdd       (),
        .out_base_temp      (),
        .out_base_period    (),
        .out_delta_vdd      (),
        .out_delta_temp     (),
        .out_delta_period   (),
        .out_snap_pc        (forensic_pc),
        .out_snap_priv      (),
        .out_snap_bad_pc    (),
        .log_write_ptr      (w_log_wp),
        .log_read_ptr       (w_log_rp),
        .log_count          (w_log_cnt),
        .log_full           (w_log_full),
        .log_empty          (w_log_empty),
        .capture_done       (w_forensic_captured),
        .read_valid         (forensic_read_valid),
        .unit_ready         (w_forensic_ready)
    );

// ============================================================
// MODULE 9 - Recovery FSM
// ============================================================

    kavach_recovery_fsm #(
        .NUM_MODULES      (NUM_MODULES),
        .STEP_HOLD_CYCLES (STEP_HOLD_CYCLES),
        .MAX_RETRY        (MAX_RETRY)
    ) u_recovery_fsm (
        .clk                (clk),
        .rst_n              (rst_n),
        .recovery_trigger   (w_recovery_trigger),
        .last_threat_level  (w_threat_level),
        .last_attack_type   (w_attack_type),
        .last_response      (w_active_response),
        .integ_check_done   (integ_check_done),
        .integ_check_pass   (integ_check_pass),
        .module_restore_ack (module_restore_ack),
        .sys_stable         (sys_stable),
        .threat_clear       (w_threat_cleared),
        .integ_check_req    (integ_check_req),
        .clk_restore        (clk_restore),
        .clk_div_recover    (clk_div_recover),
        .module_restore     (module_restore),
        .bus_restore        (bus_restore),
        .dma_restore        (dma_restore),
        .debug_restore      (w_dbg_restore),
        .puf_restore        (w_puf_restore),
        .recovery_state     (recovery_state),
        .recovery_done      (w_recovery_done),
        .recovery_failed    (recovery_failed),
        .recovery_ready     (w_recovery_ready),
        .retry_count        (w_retry_cnt),
        .step_timer         (w_step_timer),
        .permanent_lockdown (permanent_lockdown)
    );

endmodule

// ============================================================
// END: kavach_top.v - ALL 9 MODULES INSTANTIATED
// ============================================================
