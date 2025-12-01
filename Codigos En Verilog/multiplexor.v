`timescale 1ns/1ns

module multiplexor(
    input sel,
    input [4:0] A,
    input [4:0] B,
    output reg [4:0] Sal
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

