`timescale 1ns/1ns

module ALU_Control(
    input [2:0] ALUOp,      
    input [5:0] funct,
    output reg [3:0] ALU_Control
);
    always @(*) begin
        case(ALUOp)
            3'b000: ALU_Control = 4'b0010; 
            3'b001: ALU_Control = 4'b0110;
            
            3'b010: begin 
                case(funct)
                    6'b100000: ALU_Control = 4'b0010; 
                    6'b100010: ALU_Control = 4'b0110; 
                    6'b100100: ALU_Control = 4'b0000; 
                    6'b100101: ALU_Control = 4'b0001; 
                    6'b100110: ALU_Control = 4'b0011; 
                    6'b101010: ALU_Control = 4'b0111; 
                    6'b100111: ALU_Control = 4'b1100; 
                    default:   ALU_Control = 4'b0000;
                endcase
            end
            
            
            3'b011: ALU_Control = 4'b0000; 
            3'b100: ALU_Control = 4'b0001; 
            3'b101: ALU_Control = 4'b0011; 
            3'b110: ALU_Control = 4'b0111; 
            
            default: ALU_Control = 4'b0000;
        endcase
    end
endmodule

