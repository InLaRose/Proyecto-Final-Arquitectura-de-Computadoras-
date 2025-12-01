`timescale 1ns/1ns

module Instruction_Memory(
    input [31:0] address,
    output [31:0] instruction
);

    reg [31:0] memory [0:255];

    initial begin
        $readmemb("instructions.txt", memory);
    end

    assign instruction = memory[address[31:2]];

endmodule

