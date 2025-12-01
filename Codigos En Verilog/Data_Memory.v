`timescale 1ns/1ns

module Data_Memory(
    input clk,
    input MemWrite,
    input MemRead,
    input [31:0] address,
    input [31:0] write_data,
    output reg [31:0] read_data
);

    reg [31:0] memory [0:255];

    initial begin
        $readmemb("data.txt", memory);
    end

    always @(*) begin
        if (MemRead)
            read_data = memory[address[31:2]];
        else
            read_data = 32'b0;
    end

    always @(posedge clk) begin
        if (MemWrite)
            memory[address[31:2]] <= write_data;
    end

endmodule

