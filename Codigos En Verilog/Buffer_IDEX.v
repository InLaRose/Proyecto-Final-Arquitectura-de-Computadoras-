`timescale 1ns/1ns

module Buffer_IDEX(
    input clk,
    input RegDst_in,
    input ALUSrc_in,
    input MemtoReg_in,
    input RegWrite_in,
    input MemRead_in,
    input MemWrite_in,
    input Branch_in,
    input [2:0] ALUOp_in,
    input [31:0] PC_in,
    input [31:0] ReadData1_in,
    input [31:0] ReadData2_in,
    input [31:0] SignExtend_in,
    input [4:0] rs_in,
    input [4:0] rt_in,
    input [4:0] rd_in,
    output reg RegDst_out,
    output reg ALUSrc_out,
    output reg MemtoReg_out,
    output reg RegWrite_out,
    output reg MemRead_out,
    output reg MemWrite_out,
    output reg Branch_out,
    output reg [2:0] ALUOp_out,
    output reg [31:0] PC_out,
    output reg [31:0] ReadData1_out,
    output reg [31:0] ReadData2_out,
    output reg [31:0] SignExtend_out,
    output reg [4:0] rs_out,
    output reg [4:0] rt_out,
    output reg [4:0] rd_out
);

    initial begin
        RegDst_out = 0;
        ALUSrc_out = 0;
        MemtoReg_out = 0;
        RegWrite_out = 0;
        MemRead_out = 0;
        MemWrite_out = 0;
        Branch_out = 0;
        ALUOp_out = 0;
        PC_out = 0;
        ReadData1_out = 0;
        ReadData2_out = 0;
        SignExtend_out = 0;
        rs_out = 0;
        rt_out = 0;
        rd_out = 0;
    end

    always @(posedge clk) begin
        RegDst_out <= RegDst_in;
        ALUSrc_out <= ALUSrc_in;
        MemtoReg_out <= MemtoReg_in;
        RegWrite_out <= RegWrite_in;
        MemRead_out <= MemRead_in;
        MemWrite_out <= MemWrite_in;
        Branch_out <= Branch_in;
        ALUOp_out <= ALUOp_in;
        PC_out <= PC_in;
        ReadData1_out <= ReadData1_in;
        ReadData2_out <= ReadData2_in;
        SignExtend_out <= SignExtend_in;
        rs_out <= rs_in;
        rt_out <= rt_in;
        rd_out <= rd_in;
    end

endmodule

