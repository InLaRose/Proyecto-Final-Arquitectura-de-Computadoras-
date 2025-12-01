`timescale 1ns/1ns

module Buffer_IFID(
    input clk,
    input flush,             
    input [31:0] PC_in,
    input [31:0] instruction_in,
    output reg [31:0] PC_out,
    output reg [31:0] instruction_out
);
    initial begin
        PC_out = 0;
        instruction_out = 0;
    end

    always @(posedge clk) begin
        if (flush) begin
            PC_out <= 0;
            instruction_out <= 0; 
        end else begin
            PC_out <= PC_in;
            instruction_out <= instruction_in;
        end
    end
endmodule

