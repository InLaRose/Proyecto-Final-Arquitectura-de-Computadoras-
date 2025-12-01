`timescale 1ns/1ns

module ALU(
    input [31:0] A,
    input [31:0] B,
    input [3:0] ALU_Control,
    output reg [31:0] ALU_Result,
    output Zero
);
    always @(*) begin
        case(ALU_Control)
            4'b0000: ALU_Result = A & B;       
            4'b0001: ALU_Result = A | B;       
            4'b0010: ALU_Result = A + B;       
            4'b0011: ALU_Result = A ^ B;       
            4'b0110: ALU_Result = A - B;       
            4'b0111: ALU_Result = (A < B) ? 1 : 0; 
            4'b1100: ALU_Result = ~(A | B);    
            default: ALU_Result = 0;
        endcase
    end

    assign Zero = (ALU_Result == 0) ? 1 : 0;
endmodule
