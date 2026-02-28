
`timescale 1ns / 1ps

module kavach_recovery_fsm #(
    parameter THREAT_WIDTH      = 3,
    parameter RESP_WIDTH        = 3,
    parameter ATTACK_TYPE_WIDTH = 4,
    parameter NUM_MODULES       = 8,
    parameter STEP_HOLD_CYCLES  = 32'd256,
    parameter INTEG_TIMEOUT     = 32'd1024,
    parameter MAX_RETRY         = 3'd3
)(
    input  wire                          clk,
    input  wire                          rst_n,

    input  wire                          recovery_trigger,
    input  wire [THREAT_WIDTH-1:0]       last_threat_level,
    input  wire [ATTACK_TYPE_WIDTH-1:0]  last_attack_type,
    input  wire [RESP_WIDTH-1:0]         last_response,

    input  wire                          integ_check_done,
    input  wire                          integ_check_pass,

    input  wire [NUM_MODULES-1:0]        module_restore_ack,

    input  wire                          sys_stable,
    input  wire                          threat_clear,

    output reg                           integ_check_req,
    output reg                           clk_restore,
    output reg  [3:0]                    clk_div_recover,
    output reg  [NUM_MODULES-1:0]        module_restore,
    output reg                           bus_restore,
    output reg                           dma_restore,
    output reg                           debug_restore,
    output reg                           puf_restore,

    output reg  [3:0]                    recovery_state,
    output reg                           recovery_done,
    output reg                           recovery_failed,
    output reg                           recovery_ready,
    output reg  [2:0]                    retry_count,
    output reg  [31:0]                   step_timer,
    output reg                           permanent_lockdown
);

    // ========================================================
    // FSM States
    // ========================================================

    localparam REC_IDLE        = 4'd0,
               REC_INIT        = 4'd1,
               REC_INTEG_CHECK = 4'd2,
               REC_CLK_RAMP    = 4'd3,
               REC_BUS_RESTORE = 4'd4,
               REC_DMA_RESTORE = 4'd5,
               REC_MOD_RESTORE = 4'd6,
               REC_VALIDATE    = 4'd7,
               REC_DONE        = 4'd8,
               REC_FAILED      = 4'd9,
               REC_PERM_LOCK   = 4'd10;

    reg [3:0] state, next_state, state_prev;

    // ========================================================
    // Timers
    // ========================================================

    reg [31:0] step_cnt;
    reg [31:0] integ_cnt;

    wire step_done      = (step_cnt  >= STEP_HOLD_CYCLES);
    wire integ_timeout  = (integ_cnt >= INTEG_TIMEOUT);

    // ========================================================
    // Internal
    // ========================================================

    reg [NUM_MODULES-1:0] modules_pending;
    reg [1:0]             clk_ramp_step;
    reg [7:0]             init_cnt;
    localparam INIT_CYCLES = 8'd8;

    // ========================================================
    // FSM Sequential
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= REC_IDLE;
            state_prev <= REC_IDLE;
        end
        else begin
            state_prev <= state;
            state      <= next_state;
        end
    end

    // ========================================================
    // FSM Next State Logic
    // ========================================================

    always @(*) begin
        next_state = state;

        case (state)
            REC_IDLE:
                if (recovery_trigger && recovery_ready && !permanent_lockdown)
                    next_state = REC_INIT;

            REC_INIT:
                if (step_done)
                    next_state = REC_INTEG_CHECK;

            REC_INTEG_CHECK:
                if (integ_timeout)
                    next_state = REC_FAILED;
                else if (integ_check_done && integ_check_pass)
                    next_state = REC_CLK_RAMP;
                else if (integ_check_done && !integ_check_pass)
                    next_state = REC_FAILED;

            REC_CLK_RAMP:
                if (step_done && clk_ramp_step == 2'd3)
                    next_state = REC_BUS_RESTORE;

            REC_BUS_RESTORE:
                if (step_done)
                    next_state = REC_DMA_RESTORE;

            REC_DMA_RESTORE:
                if (step_done)
                    next_state = REC_MOD_RESTORE;

            REC_MOD_RESTORE:
                if (modules_pending == {NUM_MODULES{1'b0}})
                    next_state = REC_VALIDATE;

            REC_VALIDATE:
                if (!threat_clear)
                    next_state = REC_FAILED;
                else if (sys_stable && step_done)
                    next_state = REC_DONE;

            REC_DONE:
                next_state = REC_IDLE;

            REC_FAILED:
                if (retry_count >= MAX_RETRY)
                    next_state = REC_PERM_LOCK;
                else
                    next_state = REC_INIT;

            REC_PERM_LOCK:
                next_state = REC_PERM_LOCK;

            default:
                next_state = REC_IDLE;
        endcase
    end

    // ========================================================
    // Step Timer
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            step_cnt <= 0;
        else if (state != state_prev)
            step_cnt <= 0;
        else
            step_cnt <= step_cnt + 1'b1;
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            step_timer <= 0;
        else
            step_timer <= step_cnt;
    end

    // ========================================================
    // Integrity Timeout Counter
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            integ_cnt <= 0;
        else if (state == REC_INTEG_CHECK)
            integ_cnt <= integ_cnt + 1'b1;
        else
            integ_cnt <= 0;
    end

    // ========================================================
    // Clock Ramp
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            clk_ramp_step <= 0;
        else if (state != REC_CLK_RAMP)
            clk_ramp_step <= 0;
        else if (step_done && clk_ramp_step < 2'd3)
            clk_ramp_step <= clk_ramp_step + 1'b1;
    end

    // ========================================================
    // Module Restore Tracking (FIXED)
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            modules_pending <= 0;
        else if (next_state == REC_MOD_RESTORE && state != REC_MOD_RESTORE)
            modules_pending <= {NUM_MODULES{1'b1}};
        else if (state == REC_MOD_RESTORE)
            modules_pending <= modules_pending & ~module_restore_ack;
    end

    // ========================================================
    // Retry Counter
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            retry_count <= 0;
        else if (state == REC_IDLE)
            retry_count <= 0;
        else if (state == REC_FAILED && next_state == REC_INIT)
            retry_count <= retry_count + 1'b1;
    end

    // ========================================================
    // Output Logic (FIXED)
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            integ_check_req   <= 0;
            clk_restore       <= 0;
            clk_div_recover   <= 4'h1;
            module_restore    <= 0;
            bus_restore       <= 0;
            dma_restore       <= 0;
            debug_restore     <= 0;
            puf_restore       <= 0;
            recovery_done     <= 0;
            recovery_failed   <= 0;
            recovery_ready    <= 1'b1;
            permanent_lockdown<= 1'b0;
            recovery_state    <= REC_IDLE;
            init_cnt          <= 0;
        end
        else begin
            recovery_state     <= state;
            integ_check_req    <= 0;
            clk_restore        <= 0;
            module_restore     <= 0;
            bus_restore        <= 0;
            dma_restore        <= 0;
            debug_restore      <= 0;
            puf_restore        <= 0;
            recovery_done      <= 0;
            recovery_failed    <= 0;
            recovery_ready     <= 0;
            permanent_lockdown <= 0;

            if (init_cnt < INIT_CYCLES)
                init_cnt <= init_cnt + 1'b1;

            case (state)

                REC_IDLE: begin
                    recovery_ready  <= 1'b1;
                    clk_div_recover <= 4'h1;
                end

                REC_INIT:
                    clk_div_recover <= 4'h8;

                REC_INTEG_CHECK: begin
                    integ_check_req <= 1'b1;
                    clk_div_recover <= 4'h8;
                end

                REC_CLK_RAMP: begin
                    case (clk_ramp_step)
                        0: clk_div_recover <= 4'h8;
                        1: clk_div_recover <= 4'h4;
                        2: clk_div_recover <= 4'h2;
                        3: begin
                            clk_div_recover <= 4'h1;
                            clk_restore     <= 1'b1;
                        end
                    endcase
                end

                REC_BUS_RESTORE:
                    bus_restore <= 1'b1;

                REC_DMA_RESTORE: begin
                    bus_restore <= 1'b1;
                    dma_restore <= 1'b1;
                end

                REC_MOD_RESTORE: begin
                    bus_restore    <= 1'b1;
                    dma_restore    <= 1'b1;
                    module_restore <= modules_pending;
                    puf_restore    <= (last_attack_type != 4'h4);
                end

                REC_VALIDATE: begin
                    module_restore <= {NUM_MODULES{1'b1}};
                    puf_restore    <= 1'b1;
                    debug_restore  <= (last_threat_level <= 3'd2);
                end

                REC_DONE: begin
                    recovery_done  <= 1'b1;
                    recovery_ready <= 1'b1;
                end

                REC_FAILED: begin
                    recovery_failed <= 1'b1;
                    recovery_ready  <= (retry_count < MAX_RETRY);
                end

                REC_PERM_LOCK: begin
                    permanent_lockdown <= 1'b1;
                    recovery_failed    <= 1'b1;
                    clk_div_recover    <= 4'hF;
                end
            endcase
        end
    end

endmodule
