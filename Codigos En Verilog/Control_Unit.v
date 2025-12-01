`timescale 1ns/1ns

module Control_Unit(
    input [5:0] opcode,
    output reg RegDst,
    output reg ALUSrc,
    output reg MemtoReg,
    output reg RegWrite,
    output reg MemRead,
    output reg MemWrite,
    output reg Branch,
	output reg Jump,        
    output reg [2:0] ALUOp
);

always @(*) begin
        
        RegDst = 0; ALUSrc = 0; MemtoReg = 0; RegWrite = 0;
        MemRead = 0; MemWrite = 0; Branch = 0; Jump = 0;
        ALUOp = 3'b000;

        case(opcode)
            6'b000000: begin  
                RegDst = 1; RegWrite = 1; ALUOp = 3'b010;
            end
            6'b000010: begin  
                Jump = 1;
            end
            6'b100011: begin  
                ALUSrc = 1; MemtoReg = 1; RegWrite = 1; MemRead = 1; ALUOp = 3'b000;
            end
            6'b101011: begin  
                ALUSrc = 1; MemWrite = 1; ALUOp = 3'b000;
            end
            6'b000100: begin  
                Branch = 1; ALUOp = 3'b001;
            end
            6'b001000: begin  
                ALUSrc = 1; RegWrite = 1; ALUOp = 3'b000; 
            end
            6'b001100: begin  
                ALUSrc = 1; RegWrite = 1; ALUOp = 3'b011;
            end
            6'b001101: begin  
                ALUSrc = 1; RegWrite = 1; ALUOp = 3'b100; 
            end
            6'b001110: begin  
                ALUSrc = 1; RegWrite = 1; ALUOp = 3'b101; 
            end
            6'b001010: begin  
                ALUSrc = 1; RegWrite = 1; ALUOp = 3'b110; 
            end
            default: begin
                
            end
        endcase
    end
endmodule

