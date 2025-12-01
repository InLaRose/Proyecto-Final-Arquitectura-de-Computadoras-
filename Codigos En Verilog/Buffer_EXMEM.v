`timescale 1ns/1ns

module Buffer_EXMEM(
    input clk,
    input MemtoReg_in,
    input RegWrite_in,
    input MemRead_in,
    input MemWrite_in,
    input Branch_in,
    input [31:0] Branch_addr_in,
    input Zero_in,
    input [31:0] ALU_result_in,
    input [31:0] WriteData_in,
    input [4:0] WriteReg_in,
    output reg MemtoReg_out,
    output reg RegWrite_out,
    output reg MemRead_out,
    output reg MemWrite_out,
    output reg Branch_out,
    output reg [31:0] Branch_addr_out,
    output reg Zero_out,
    output reg [31:0] ALU_result_out,
    output reg [31:0] WriteData_out,
    output reg [4:0] WriteReg_out
);

    initial begin
        MemtoReg_out = 0;
        RegWrite_out = 0;
        MemRead_out = 0;
        MemWrite_out = 0;
        Branch_out = 0;
        Branch_addr_out = 0;
        Zero_out = 0;
        ALU_result_out = 0;
        WriteData_out = 0;
        WriteReg_out = 0;
    end

    always @(posedge clk) begin
        MemtoReg_out <= MemtoReg_in;
        RegWrite_out <= RegWrite_in;
        MemRead_out <= MemRead_in;
        MemWrite_out <= MemWrite_in;
        Branch_out <= Branch_in;
        Branch_addr_out <= Branch_addr_in;
        Zero_out <= Zero_in;
        ALU_result_out <= ALU_result_in;
        WriteData_out <= WriteData_in;
        WriteReg_out <= WriteReg_in;
    end

endmodule

