// ============================================================
// KAVACH IP - Module 8: Forensic Capture Unit (FINAL)
// ============================================================

`timescale 1ns / 1ps

module kavach_forensic_capture #(
    parameter LOG_DEPTH         = 8,
    parameter LOG_ADDR_WIDTH    = 3,

    parameter ADC_WIDTH         = 12,
    parameter PC_WIDTH          = 32,
    parameter SCORE_WIDTH       = 8,
    parameter ATTACK_TYPE_WIDTH = 4,
    parameter TIMESTAMP_WIDTH   = 48,

    parameter THREAT_WIDTH      = 3,
    parameter RESP_WIDTH        = 3,
    parameter PRIV_WIDTH        = 2
)(
    input  wire                          clk,
    input  wire                          rst_n,

    input  wire                          capture_trigger,
    input  wire                          threat_valid,

    input  wire [THREAT_WIDTH-1:0]       threat_level,
    input  wire [ATTACK_TYPE_WIDTH-1:0]  attack_type,
    input  wire [SCORE_WIDTH-1:0]        threat_score,
    input  wire [RESP_WIDTH-1:0]         response_taken,

    input  wire [ADC_WIDTH-1:0]          snap_vdd,
    input  wire [ADC_WIDTH-1:0]          snap_idd,
    input  wire [ADC_WIDTH-1:0]          snap_temp,
    input  wire [15:0]                   snap_period,
    input  wire [15:0]                   snap_ipc,

    input  wire [ADC_WIDTH-1:0]          base_vdd,
    input  wire [ADC_WIDTH-1:0]          base_idd,
    input  wire [ADC_WIDTH-1:0]          base_temp,
    input  wire [15:0]                   base_period,
    input  wire [15:0]                   base_ipc,

    input  wire [PC_WIDTH-1:0]           snap_pc,
    input  wire [PRIV_WIDTH-1:0]         snap_priv,
    input  wire [PC_WIDTH-1:0]           snap_bad_pc,

    input  wire [ADC_WIDTH-1:0]          delta_vdd,
    input  wire [ADC_WIDTH-1:0]          delta_temp,
    input  wire [15:0]                   delta_period,

    input  wire [LOG_ADDR_WIDTH-1:0]     read_slot,
    input  wire                          read_req,
    input  wire                          read_ack,

    output reg  [TIMESTAMP_WIDTH-1:0]    out_timestamp,
    output reg  [THREAT_WIDTH-1:0]       out_threat_level,
    output reg  [ATTACK_TYPE_WIDTH-1:0]  out_attack_type,
    output reg  [SCORE_WIDTH-1:0]        out_threat_score,
    output reg  [RESP_WIDTH-1:0]         out_response_taken,
    output reg  [ADC_WIDTH-1:0]          out_snap_vdd,
    output reg  [ADC_WIDTH-1:0]          out_snap_idd,
    output reg  [ADC_WIDTH-1:0]          out_snap_temp,
    output reg  [15:0]                   out_snap_period,
    output reg  [15:0]                   out_snap_ipc,
    output reg  [ADC_WIDTH-1:0]          out_base_vdd,
    output reg  [ADC_WIDTH-1:0]          out_base_temp,
    output reg  [15:0]                   out_base_period,
    output reg  [ADC_WIDTH-1:0]          out_delta_vdd,
    output reg  [ADC_WIDTH-1:0]          out_delta_temp,
    output reg  [15:0]                   out_delta_period,
    output reg  [PC_WIDTH-1:0]           out_snap_pc,
    output reg  [PRIV_WIDTH-1:0]         out_snap_priv,
    output reg  [PC_WIDTH-1:0]           out_snap_bad_pc,

    output reg  [LOG_ADDR_WIDTH-1:0]     log_write_ptr,
    output reg  [LOG_ADDR_WIDTH-1:0]     log_read_ptr,
    output reg  [LOG_ADDR_WIDTH:0]       log_count,
    output reg                           log_full,
    output reg                           log_empty,
    output reg                           capture_done,
    output reg                           read_valid,
    output reg                           unit_ready
);

    // ========================================================
    // Internal Storage
    // ========================================================

    reg [TIMESTAMP_WIDTH-1:0] timestamp_cnt;

    reg [TIMESTAMP_WIDTH-1:0]   mem_timestamp   [0:LOG_DEPTH-1];
    reg [THREAT_WIDTH-1:0]      mem_threat_lvl  [0:LOG_DEPTH-1];
    reg [ATTACK_TYPE_WIDTH-1:0] mem_attack_type [0:LOG_DEPTH-1];
    reg [SCORE_WIDTH-1:0]       mem_score       [0:LOG_DEPTH-1];
    reg [RESP_WIDTH-1:0]        mem_response    [0:LOG_DEPTH-1];
    reg [ADC_WIDTH-1:0]         mem_vdd         [0:LOG_DEPTH-1];
    reg [ADC_WIDTH-1:0]         mem_idd         [0:LOG_DEPTH-1];
    reg [ADC_WIDTH-1:0]         mem_temp        [0:LOG_DEPTH-1];
    reg [15:0]                  mem_period      [0:LOG_DEPTH-1];
    reg [15:0]                  mem_ipc         [0:LOG_DEPTH-1];
    reg [ADC_WIDTH-1:0]         mem_base_vdd    [0:LOG_DEPTH-1];
    reg [ADC_WIDTH-1:0]         mem_base_temp   [0:LOG_DEPTH-1];
    reg [15:0]                  mem_base_period [0:LOG_DEPTH-1];
    reg [ADC_WIDTH-1:0]         mem_delta_vdd   [0:LOG_DEPTH-1];
    reg [ADC_WIDTH-1:0]         mem_delta_temp  [0:LOG_DEPTH-1];
    reg [15:0]                  mem_delta_per   [0:LOG_DEPTH-1];
    reg [PC_WIDTH-1:0]          mem_pc          [0:LOG_DEPTH-1];
    reg [PRIV_WIDTH-1:0]        mem_priv        [0:LOG_DEPTH-1];
    reg [PC_WIDTH-1:0]          mem_bad_pc      [0:LOG_DEPTH-1];

    reg [LOG_DEPTH-1:0] slot_locked;
    reg [LOG_ADDR_WIDTH-1:0] wr_ptr;
    reg [LOG_ADDR_WIDTH:0] event_cnt;

    localparam CAP_IDLE  = 2'd0,
               CAP_WRITE = 2'd1,
               CAP_DONE  = 2'd2;

    reg [1:0] cap_state;

    reg [7:0] init_cnt;
    localparam INIT_CYCLES = 8'd8;

    // ========================================================
    // Timestamp
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            timestamp_cnt <= 0;
        else
            timestamp_cnt <= timestamp_cnt + 1'b1;
    end

    // ========================================================
    // Capture FSM
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            cap_state    <= CAP_IDLE;
            capture_done <= 1'b0;
            wr_ptr       <= 0;
            event_cnt    <= 0;
            slot_locked  <= 0;
            init_cnt     <= 0;
            unit_ready   <= 1'b0;
        end
        else begin
            if (init_cnt < INIT_CYCLES) begin
                init_cnt   <= init_cnt + 1'b1;
                unit_ready <= 1'b0;
            end else
                unit_ready <= 1'b1;

            case (cap_state)

                CAP_IDLE: begin
                    capture_done <= 1'b0;
                    if (capture_trigger && threat_valid && unit_ready)
                        cap_state <= CAP_WRITE;
                end

                CAP_WRITE: begin
                    if (!slot_locked[wr_ptr]) begin
                        mem_timestamp   [wr_ptr] <= timestamp_cnt;
                        mem_threat_lvl  [wr_ptr] <= threat_level;
                        mem_attack_type [wr_ptr] <= attack_type;
                        mem_score       [wr_ptr] <= threat_score;
                        mem_response    [wr_ptr] <= response_taken;
                        mem_vdd         [wr_ptr] <= snap_vdd;
                        mem_idd         [wr_ptr] <= snap_idd;
                        mem_temp        [wr_ptr] <= snap_temp;
                        mem_period      [wr_ptr] <= snap_period;
                        mem_ipc         [wr_ptr] <= snap_ipc;
                        mem_base_vdd    [wr_ptr] <= base_vdd;
                        mem_base_temp   [wr_ptr] <= base_temp;
                        mem_base_period [wr_ptr] <= base_period;
                        mem_delta_vdd   [wr_ptr] <= delta_vdd;
                        mem_delta_temp  [wr_ptr] <= delta_temp;
                        mem_delta_per   [wr_ptr] <= delta_period;
                        mem_pc          [wr_ptr] <= snap_pc;
                        mem_priv        [wr_ptr] <= snap_priv;
                        mem_bad_pc      [wr_ptr] <= snap_bad_pc;

                        slot_locked[wr_ptr] <= 1'b1;

                        wr_ptr <= (wr_ptr == LOG_DEPTH-1) ? 0 : wr_ptr + 1'b1;
                        if (event_cnt < LOG_DEPTH)
                            event_cnt <= event_cnt + 1'b1;
                    end
                    cap_state <= CAP_DONE;
                end

                CAP_DONE: begin
                    capture_done <= 1'b1;
                    cap_state    <= CAP_IDLE;
                end
            endcase
        end
    end

    // ========================================================
    // Read Interface (Read-Once)
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            read_valid <= 1'b0;
        end
        else begin
            if (read_req && slot_locked[read_slot]) begin
                out_timestamp      <= mem_timestamp   [read_slot];
                out_threat_level   <= mem_threat_lvl  [read_slot];
                out_attack_type    <= mem_attack_type [read_slot];
                out_threat_score   <= mem_score       [read_slot];
                out_response_taken <= mem_response    [read_slot];
                out_snap_vdd       <= mem_vdd         [read_slot];
                out_snap_idd       <= mem_idd         [read_slot];
                out_snap_temp      <= mem_temp        [read_slot];
                out_snap_period    <= mem_period      [read_slot];
                out_snap_ipc       <= mem_ipc         [read_slot];
                out_base_vdd       <= mem_base_vdd    [read_slot];
                out_base_temp      <= mem_base_temp   [read_slot];
                out_base_period    <= mem_base_period [read_slot];
                out_delta_vdd      <= mem_delta_vdd   [read_slot];
                out_delta_temp     <= mem_delta_temp  [read_slot];
                out_delta_period   <= mem_delta_per   [read_slot];
                out_snap_pc        <= mem_pc          [read_slot];
                out_snap_priv      <= mem_priv        [read_slot];
                out_snap_bad_pc    <= mem_bad_pc      [read_slot];
                read_valid         <= 1'b1;
            end

            if (read_ack && read_valid) begin
                slot_locked[read_slot] <= 1'b0;
                read_valid <= 1'b0;
                if (event_cnt > 0)
                    event_cnt <= event_cnt - 1'b1;
            end
        end
    end

    // ========================================================
    // Status Outputs
    // ========================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            log_write_ptr <= 0;
            log_read_ptr  <= 0;
            log_count     <= 0;
            log_full      <= 1'b0;
            log_empty     <= 1'b1;
        end
        else begin
            log_write_ptr <= wr_ptr;
            log_read_ptr  <= read_slot;
            log_count     <= event_cnt;
            log_full      <= (event_cnt >= LOG_DEPTH);
            log_empty     <= (event_cnt == 0);
        end
    end

endmodule
