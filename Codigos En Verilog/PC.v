`timescale 1ns/1ns

module PC(
    input clk,
    input reset,
    input [31:0] PC_in,
    output reg [31:0] PC_out
);

    initial PC_out = 0;

    always @(posedge clk or posedge reset) begin
        if (reset)
            PC_out <= 0;
        else
            PC_out <= PC_in;
    end

endmodule
