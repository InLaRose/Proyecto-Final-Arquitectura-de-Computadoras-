`timescale 1ns/1ns

module Burrito(
    input clk,
    input RegWrite,
    input [4:0] WriteReg,
    input [31:0] WriteData,
    input [31:0] CFDE,
    input RegDst,
    output [31:0] DR1_De,
    output [31:0] DR2_De,
    output [4:0] rs_out,
    output [4:0] rt_out,
    output [4:0] rd_out,
    output [4:0] dest_sel_out
);

    wire [4:0] rs = CFDE[25:21];
    wire [4:0] rt = CFDE[20:16];
    wire [4:0] rd = CFDE[15:11];

    wire [31:0] br_dr1, br_dr2;
    wire [4:0] dest_sel;

    BR banco_regs (
        .clk(clk),
        .we(RegWrite),
        .AR1(rs),
        .AR2(rt),
        .AW(WriteReg),
        .DW(WriteData),
        .DR1(br_dr1),
        .DR2(br_dr2)
    );

    multiplexor mux_dest (
        .sel(RegDst),
        .A(rt),
        .B(rd),
        .Sal(dest_sel)
    );

    assign DR1_De = br_dr1;
    assign DR2_De = br_dr2;
    assign rs_out = rs;
    assign rt_out = rt;
    assign rd_out = rd;
    assign dest_sel_out = dest_sel;

endmodule

