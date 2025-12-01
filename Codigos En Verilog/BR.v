`timescale 1ns/1ns

module BR(
    input clk,
    input we,
    input [4:0] AR1,
    input [4:0] AR2,
    input [4:0] AW,
    input [31:0] DW,
    output reg [31:0] DR1,
    output reg [31:0] DR2
);

    reg [31:0] Banco[0:31];

    initial begin
        $readmemb("Datos.txt", Banco);
        Banco[0] = 32'b0;
    end

    always @* begin
        DR1 = Banco[AR1];
        DR2 = Banco[AR2];
    end

    always @(posedge clk) begin
        if (we && AW != 5'd0) begin
            Banco[AW] <= DW;
        end
    end

endmodule

