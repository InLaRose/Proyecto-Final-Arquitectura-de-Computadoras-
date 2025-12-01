`timescale 1ns/1ns

module add(
    input [31:0] op1,
    output [31:0] Resultado
);

    assign Resultado = op1 + 4;

endmodule

