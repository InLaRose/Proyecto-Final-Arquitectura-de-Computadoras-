`timescale 1ns/1ns

module TB_MIPS_Pipeline;

    reg clk;
    reg reset;

    MIPS_Pipeline uut (
        .clk(clk),
        .reset(reset)
    );

    initial clk = 0;
    always #10 clk = ~clk;

    initial begin
        $dumpfile("mips_pipeline.vcd");
        $dumpvars(0, TB_MIPS_Pipeline);
    end

    initial begin
        $display("========================================");
        $display("  SIMULACION PIPELINE MIPS");
        $display("========================================");
        
        reset = 1;
        #20;
        reset = 0;
        
        $display("Reset completado. Iniciando ejecucion...");
        
        $monitor("Tiempo=%0t | PC=%h | Inst=%h | ALU=%h", 
                 $time, uut.PC_current, uut.instruction, uut.ALU_result);
        
        repeat (100) @(posedge clk);
        
        $display("========================================");
        $display("  SIMULACION COMPLETADA");
        $display("========================================");
        
        $display("\nBanco de Registros:");
        $display("R0 = %h", uut.decode.banco_regs.Banco[0]);
        $display("R1 = %h", uut.decode.banco_regs.Banco[1]);
        $display("R2 = %h", uut.decode.banco_regs.Banco[2]);
        $display("R3 = %h", uut.decode.banco_regs.Banco[3]);
        $display("R4 = %h", uut.decode.banco_regs.Banco[4]);
        $display("R5 = %h", uut.decode.banco_regs.Banco[5]);
        $display("R8 (t0) = %h", uut.decode.banco_regs.Banco[8]);
        $display("R9 (t1) = %h", uut.decode.banco_regs.Banco[9]);
        $display("R10(t2) = %h", uut.decode.banco_regs.Banco[10]);
        $display("R11(t3) = %h", uut.decode.banco_regs.Banco[11]);
        $display("R12(t4) = %h", uut.decode.banco_regs.Banco[12]);
        
        $finish;
    end

endmodule

