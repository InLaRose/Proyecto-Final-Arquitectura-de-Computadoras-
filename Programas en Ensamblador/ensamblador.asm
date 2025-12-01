ADDI $t0, $zero, 10    
ADDI $t1, $zero, 5     
ADDI $t3, $zero, 5       
NOP                     
ADD $t2, $t0, $t1       
SUB $t4, $t0, $t1       
OR $t6, $t0, $t1        
SLT $t7, $t1, $t0       
NOP                     
SW $t2, 0($zero)         
NOP                      
LW $t5, 0($zero)         
NOP                      
BEQ $t3, $t1, ENCONTRADO 
NOP                     
NOP                     
# (Instrucciones que serían saltadas)
ADDI $t8, $zero, 99      
J FIN                    
ADDI $s0, $zero, 1      
J FIN                   