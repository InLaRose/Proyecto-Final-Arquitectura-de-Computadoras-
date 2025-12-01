`timescale 1ns/1ns

module Buffer_MEMWB(
    input clk,
    input MemtoReg_in,
    input RegWrite_in,
    input [31:0] MemData_in,
    input [31:0] ALU_result_in,
    input [4:0] WriteReg_in,
    output reg MemtoReg_out,
    output reg RegWrite_out,
    output reg [31:0] MemData_out,
    output reg [31:0] ALU_result_out,
    output reg [4:0] WriteReg_out
);

    initial begin
        MemtoReg_out = 0;
        RegWrite_out = 0;
        MemData_out = 0;
        ALU_result_out = 0;
        WriteReg_out = 0;
    end

    always @(posedge clk) begin
        MemtoReg_out <= MemtoReg_in;
        RegWrite_out <= RegWrite_in;
        MemData_out <= MemData_in;
        ALU_result_out <= ALU_result_in;
        WriteReg_out <= WriteReg_in;
    end

endmodule

