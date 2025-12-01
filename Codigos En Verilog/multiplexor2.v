`timescale 1ns/1ns

module multiplexor2(
    input sel,
    input [31:0] A,
    input [31:0] B,
    output reg [31:0] Sal
);

    always @* begin
        if (sel == 0) begin
            Sal = A;    
        end 
        else begin
            Sal = B;
        end
    end

endmodule
