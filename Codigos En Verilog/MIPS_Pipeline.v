`timescale 1ns/1ns

module MIPS_Pipeline(
    input clk,
    input reset
);

    wire [31:0] PC_current, PC_next, PC_plus4;
    wire [31:0] instruction;
    
    
    wire [31:0] branch_target_addr; 
    wire PCSrc;                     
    wire [31:0] jump_addr;          
    wire Jump;                      

    PC pc_reg (
        .clk(clk),
        .reset(reset),
        .PC_in(PC_next), 
        .PC_out(PC_current)
    );

    Instruction_Memory imem (
        .address(PC_current),
        .instruction(instruction)
    );

    add adder_pc (
        .op1(PC_current),
        .Resultado(PC_plus4)
    );


    wire [31:0] IFID_PC, IFID_instruction;
    wire ifid_flush;

 
    assign ifid_flush = PCSrc || Jump; 

    Buffer_IFID ifid_buffer (
        .clk(clk),
        .flush(ifid_flush),            
        .PC_in(PC_plus4),
        .instruction_in(instruction),
        .PC_out(IFID_PC),
        .instruction_out(IFID_instruction)
    );

    
    wire [5:0] opcode = IFID_instruction[31:26];
    wire [5:0] funct = IFID_instruction[5:0];
    wire [15:0] immediate = IFID_instruction[15:0];

    
    assign jump_addr = {IFID_PC[31:28], IFID_instruction[25:0], 2'b00};

    wire RegDst, ALUSrc, MemtoReg, RegWrite, MemRead, MemWrite, Branch;
    wire [2:0] ALUOp; 

    Control_Unit control (
        .opcode(opcode),
        .RegDst(RegDst),
        .ALUSrc(ALUSrc),
        .MemtoReg(MemtoReg),
        .RegWrite(RegWrite),
        .MemRead(MemRead),
        .MemWrite(MemWrite),
        .Branch(Branch),
        .Jump(Jump),       
        .ALUOp(ALUOp)      
    );

    wire [31:0] ReadData1, ReadData2;
    wire [4:0] rs, rt, rd, dest_reg;
    wire [31:0] SignExtImm;

    
    wire MEMWB_RegWrite;
    wire [4:0] MEMWB_WriteReg;
    wire [31:0] MEMWB_WriteData;

    Burrito decode (
        .clk(clk),
        .RegWrite(MEMWB_RegWrite),
        .WriteReg(MEMWB_WriteReg),
        .WriteData(MEMWB_WriteData),
        .CFDE(IFID_instruction),
        .RegDst(RegDst),
        .DR1_De(ReadData1),
        .DR2_De(ReadData2),
        .rs_out(rs),
        .rt_out(rt),
        .rd_out(rd),
        .dest_sel_out(dest_reg)
    );

    Sign_Extend sign_ext (
        .in(immediate),
        .out(SignExtImm)
    );

    
    wire IDEX_RegDst, IDEX_ALUSrc, IDEX_MemtoReg, IDEX_RegWrite;
    wire IDEX_MemRead, IDEX_MemWrite, IDEX_Branch;
    wire [2:0] IDEX_ALUOp; // CAMBIO: 3 bits en el buffer
    wire [31:0] IDEX_PC, IDEX_ReadData1, IDEX_ReadData2, IDEX_SignExtImm;
    wire [4:0] IDEX_rs, IDEX_rt, IDEX_rd;

    Buffer_IDEX idex_buffer (
        .clk(clk),
        .RegDst_in(RegDst),
        .ALUSrc_in(ALUSrc),
        .MemtoReg_in(MemtoReg),
        .RegWrite_in(RegWrite),
        .MemRead_in(MemRead),
        .MemWrite_in(MemWrite),
        .Branch_in(Branch),
        .ALUOp_in(ALUOp),         
        .PC_in(IFID_PC),
        .ReadData1_in(ReadData1),
        .ReadData2_in(ReadData2),
        .SignExtend_in(SignExtImm),
        .rs_in(rs),
        .rt_in(rt),
        .rd_in(rd),
        // Salidas
        .RegDst_out(IDEX_RegDst),
        .ALUSrc_out(IDEX_ALUSrc),
        .MemtoReg_out(IDEX_MemtoReg),
        .RegWrite_out(IDEX_RegWrite),
        .MemRead_out(IDEX_MemRead),
        .MemWrite_out(IDEX_MemWrite),
        .Branch_out(IDEX_Branch),
        .ALUOp_out(IDEX_ALUOp),   
        .PC_out(IDEX_PC),
        .ReadData1_out(IDEX_ReadData1),
        .ReadData2_out(IDEX_ReadData2),
        .SignExtend_out(IDEX_SignExtImm),
        .rs_out(IDEX_rs),
        .rt_out(IDEX_rt),
        .rd_out(IDEX_rd)
    );

   
    wire [31:0] ALU_input2;
    wire [31:0] ALU_result;
    wire [3:0] ALU_control_signal;
    wire Zero;
    wire [4:0] WriteReg_EX;
    wire [31:0] shift_result;

    
    multiplexor2 alu_mux (
        .sel(IDEX_ALUSrc),
        .A(IDEX_ReadData2),
        .B(IDEX_SignExtImm),
        .Sal(ALU_input2)
    );

    ALU_Control alu_ctrl (
        .ALUOp(IDEX_ALUOp),             
        .funct(IDEX_SignExtImm[5:0]),
        .ALU_Control(ALU_control_signal)
    );

    ALU alu (
        .A(IDEX_ReadData1),
        .B(ALU_input2),
        .ALU_Control(ALU_control_signal),
        .ALU_Result(ALU_result),
        .Zero(Zero)
    );

    
    multiplexor writereg_mux (
        .sel(IDEX_RegDst),
        .A(IDEX_rt),
        .B(IDEX_rd),
        .Sal(WriteReg_EX)
    );

    
    Shift_Left_2 shift (
        .in(IDEX_SignExtImm),
        .out(shift_result)
    );
    
    assign branch_target_addr = IDEX_PC + shift_result;

    
    wire EXMEM_MemtoReg, EXMEM_RegWrite, EXMEM_MemRead, EXMEM_MemWrite, EXMEM_Branch;
    wire [31:0] EXMEM_branch_addr, EXMEM_ALU_result, EXMEM_WriteData;
    wire [4:0] EXMEM_WriteReg;
    wire EXMEM_Zero;

    Buffer_EXMEM exmem_buffer (
        .clk(clk),
        .MemtoReg_in(IDEX_MemtoReg),
        .RegWrite_in(IDEX_RegWrite),
        .MemRead_in(IDEX_MemRead),
        .MemWrite_in(IDEX_MemWrite),
        .Branch_in(IDEX_Branch),
        .Branch_addr_in(branch_target_addr),
        .Zero_in(Zero),
        .ALU_result_in(ALU_result),
        .WriteData_in(IDEX_ReadData2),
        .WriteReg_in(WriteReg_EX),
        // Salidas
        .MemtoReg_out(EXMEM_MemtoReg),
        .RegWrite_out(EXMEM_RegWrite),
        .MemRead_out(EXMEM_MemRead),
        .MemWrite_out(EXMEM_MemWrite),
        .Branch_out(EXMEM_Branch),
        .Branch_addr_out(EXMEM_branch_addr),
        .Zero_out(EXMEM_Zero),
        .ALU_result_out(EXMEM_ALU_result),
        .WriteData_out(EXMEM_WriteData),
        .WriteReg_out(EXMEM_WriteReg)
    );

   
    wire [31:0] MemData;

    Data_Memory dmem (
        .clk(clk),
        .MemWrite(EXMEM_MemWrite),
        .MemRead(EXMEM_MemRead),
        .address(EXMEM_ALU_result),
        .write_data(EXMEM_WriteData),
        .read_data(MemData)
    );

    
    assign PCSrc = EXMEM_Branch & EXMEM_Zero;

    
    wire MEMWB_MemtoReg;
    wire [31:0] MEMWB_MemData, MEMWB_ALU_result_WB;

    Buffer_MEMWB memwb_buffer (
        .clk(clk),
        .MemtoReg_in(EXMEM_MemtoReg),
        .RegWrite_in(EXMEM_RegWrite),
        .MemData_in(MemData),
        .ALU_result_in(EXMEM_ALU_result),
        .WriteReg_in(EXMEM_WriteReg),
        // Salidas
        .MemtoReg_out(MEMWB_MemtoReg),
        .RegWrite_out(MEMWB_RegWrite),
        .MemData_out(MEMWB_MemData),
        .ALU_result_out(MEMWB_ALU_result_WB),
        .WriteReg_out(MEMWB_WriteReg)
    );

   
    multiplexor2 wb_mux (
        .sel(MEMWB_MemtoReg),
        .A(MEMWB_ALU_result_WB),
        .B(MEMWB_MemData),
        .Sal(MEMWB_WriteData) 
    );

    
    assign PC_next = (PCSrc) ? EXMEM_branch_addr : 
                     (Jump)  ? jump_addr : 
                     PC_plus4;

endmodule
