import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import re

class MipsDecoder:
    """
    Se encarga de la lógica de decodificación de instrucciones MIPS.
    Soporta R-TYPE, I-TYPE y J-TYPE.
    """
    
    # Tabla de instrucciones escalable.
    INSTRUCTION_TABLE = {
        # R-TYPE (opcode = 0)
        'add': {'type': 'R', 'opcode': 0b000000, 'funct': 0b100000},
        'sub': {'type': 'R', 'opcode': 0b000000, 'funct': 0b100010},
        'and': {'type': 'R', 'opcode': 0b000000, 'funct': 0b100100},
        'or':  {'type': 'R', 'opcode': 0b000000, 'funct': 0b100101},
        'slt': {'type': 'R', 'opcode': 0b000000, 'funct': 0b101010},
        
        # I-TYPE - Aritméticas/Lógicas
        'addi': {'type': 'I', 'opcode': 0b001000},
        'andi': {'type': 'I', 'opcode': 0b001100},
        'ori':  {'type': 'I', 'opcode': 0b001101},
        'xori': {'type': 'I', 'opcode': 0b001110},
        'slti': {'type': 'I', 'opcode': 0b001010},
        
        # I-TYPE - Control de flujo
        'beq':  {'type': 'I', 'opcode': 0b000100, 'branch': True},
        
        # I-TYPE - Memoria
        'lw':   {'type': 'I', 'opcode': 0b100011, 'memory': True},
        'sw':   {'type': 'I', 'opcode': 0b101011, 'memory': True},
        
        # J-TYPE
        'j':    {'type': 'J', 'opcode': 0b000010},
    }

    def __init__(self):
        self.labels = {}  # Diccionario para almacenar etiquetas y sus direcciones
        self.current_address = 0  # Dirección actual en bytes

    def parse_register(self, reg_str):
        """Convierte un string de registro (ej. "$10", "$s0") a su número entero."""
        reg_str = reg_str.strip().replace(',', '')
        if not reg_str.startswith('$'):
            raise ValueError(f"Formato de registro inválido: '{reg_str}'. Debe empezar con '$'.")
        
        # Mapa de registros con nombre
        reg_names = {
            'zero': 0, 'at': 1,
            'v0': 2, 'v1': 3,
            'a0': 4, 'a1': 5, 'a2': 6, 'a3': 7,
            't0': 8, 't1': 9, 't2': 10, 't3': 11, 't4': 12, 't5': 13, 't6': 14, 't7': 15,
            's0': 16, 's1': 17, 's2': 18, 's3': 19, 's4': 20, 's5': 21, 's6': 22, 's7': 23,
            't8': 24, 't9': 25,
            'k0': 26, 'k1': 27,
            'gp': 28, 'sp': 29, 'fp': 30, 'ra': 31
        }
        
        reg_name = reg_str[1:].lower()
        
        # Si es un nombre de registro, convertirlo
        if reg_name in reg_names:
            return reg_names[reg_name]
        
        # Si no, intentar parsearlo como número
        try:
            reg_num = int(reg_name)
            if not (0 <= reg_num <= 31):
                raise ValueError(f"Número de registro fuera de rango (0-31): {reg_str}")
            return reg_num
        except ValueError:
            raise ValueError(f"No se pudo parsear el registro: '{reg_str}'")

    def parse_immediate(self, imm_str, bits=16):
        """Parsea un valor inmediato y valida que quepa en el número de bits especificado."""
        imm_str = imm_str.strip().replace(',', '')
        
        try:
            # Soportar hexadecimal (0x...) y decimal
            if imm_str.startswith('0x'):
                immediate = int(imm_str, 16)
            else:
                immediate = int(imm_str)
            
            # Validar rango
            max_val = (1 << (bits - 1)) - 1  # Máximo valor positivo
            min_val = -(1 << (bits - 1))      # Mínimo valor negativo
            
            if not (min_val <= immediate <= max_val):
                raise ValueError(f"Inmediato fuera de rango ({min_val} a {max_val}): {immediate}")
            
            # Convertir a representación sin signo de n bits
            if immediate < 0:
                immediate = (1 << bits) + immediate
                
            return immediate
            
        except ValueError as e:
            raise ValueError(f"No se pudo parsear el inmediato '{imm_str}': {e}")

    def parse_memory_operand(self, operand):
        """
        Parsea operandos de memoria en formato: offset($base)
        Retorna: (offset, base_register)
        """
        match = re.match(r'([+-]?\d+)\(\$(\w+)\)', operand.strip())
        if not match:
            raise ValueError(f"Formato de memoria inválido: '{operand}'. Esperado: offset($reg)")
        
        offset_str = match.group(1)
        base_str = f"${match.group(2)}"
        
        offset = self.parse_immediate(offset_str, bits=16)
        base = self.parse_register(base_str)
        
        return offset, base

    def parse_r_type(self, operands, funct):
        """
        Parsea y codifica una instrucción Tipo R.
        Formato esperado: $rd, $rs, $rt
        """
        if len(operands) != 3:
            raise ValueError(f"Operandos insuficientes para R-type. Se esperaban 3, se obtuvieron {len(operands)}.")
        
        rd = self.parse_register(operands[0])
        rs = self.parse_register(operands[1])
        rt = self.parse_register(operands[2])
        
        opcode = 0 
        shamt = 0 
        
        # Construir la instrucción de 32 bits
        instruction_code = (
            (opcode << 26) |
            (rs     << 21) |
            (rt     << 16) |
            (rd     << 11) |
            (shamt  <<  6) |
            (funct  <<  0)
        )
        
        return instruction_code

    def parse_i_type(self, operands, opcode, instr_info):
        """
        Parsea y codifica una instrucción Tipo I.
        Formatos:
        - Aritmética/Lógica: $rt, $rs, immediate
        - Branch: $rs, $rt, label
        - Memoria: $rt, offset($base)
        """
        is_branch = instr_info.get('branch', False)
        is_memory = instr_info.get('memory', False)
        
        if is_memory:
            # Formato: LW/SW $rt, offset($base)
            if len(operands) != 2:
                raise ValueError(f"Se esperaban 2 operandos para instrucción de memoria, se obtuvieron {len(operands)}.")
            
            rt = self.parse_register(operands[0])
            immediate, rs = self.parse_memory_operand(operands[1])
            
        elif is_branch:
            # Formato: BEQ $rs, $rt, label
            if len(operands) != 3:
                raise ValueError(f"Se esperaban 3 operandos para branch, se obtuvieron {len(operands)}.")
            
            rs = self.parse_register(operands[0])
            rt = self.parse_register(operands[1])
            label = operands[2].strip().replace(',', '')
            
            # Calcular el offset relativo al PC
            if label not in self.labels:
                raise ValueError(f"Etiqueta no definida: '{label}'")
            
            target_address = self.labels[label]
            # PC apunta a la siguiente instrucción (current + 4)
            pc_next = self.current_address + 4
            offset = (target_address - pc_next) // 4  # Offset en palabras
            
            # Validar que el offset quepa en 16 bits con signo
            if not (-32768 <= offset <= 32767):
                raise ValueError(f"Offset de branch fuera de rango: {offset}")
            
            immediate = offset & 0xFFFF  # Convertir a 16 bits sin signo
            
        else:
            # Formato: Aritmética/Lógica inmediata: $rt, $rs, immediate
            if len(operands) != 3:
                raise ValueError(f"Se esperaban 3 operandos para I-type, se obtuvieron {len(operands)}.")
            
            rt = self.parse_register(operands[0])
            rs = self.parse_register(operands[1])
            immediate = self.parse_immediate(operands[2], bits=16)
        
        # Construir la instrucción de 32 bits
        instruction_code = (
            (opcode    << 26) |
            (rs        << 21) |
            (rt        << 16) |
            (immediate <<  0)
        )
        
        return instruction_code

    def parse_j_type(self, operands, opcode):
        """
        Parsea y codifica una instrucción Tipo J.
        Formato: label o dirección
        """
        if len(operands) != 1:
            raise ValueError(f"Se esperaba 1 operando para J-type, se obtuvieron {len(operands)}.")
        
        target = operands[0].strip().replace(',', '')
        
        # Si es una etiqueta
        if target in self.labels:
            target_address = self.labels[target]
        else:
            # Si es una dirección numérica
            try:
                target_address = int(target, 0)  # Soporta 0x para hex
            except ValueError:
                raise ValueError(f"Etiqueta no definida o dirección inválida: '{target}'")
        
        # La dirección de salto son los bits [27:2] de la dirección completa
        # (se asume que los bits [31:28] son los mismos que el PC actual)
        jump_address = (target_address >> 2) & 0x3FFFFFF  # 26 bits
        
        # Construir la instrucción de 32 bits
        instruction_code = (
            (opcode       << 26) |
            (jump_address <<  0)
        )
        
        return instruction_code

    def first_pass(self, input_lines):
        """
        Primera pasada: identifica etiquetas y calcula sus direcciones.
        """
        self.labels = {}
        self.current_address = 0
        
        for line in input_lines:
            line = line.strip().lower()
            
            if not line or line.startswith('#'):
                continue
            
            # Eliminar comentarios
            if '#' in line:
                line = line.split('#')[0].strip()
                if not line:
                    continue
            
            # Verificar si hay una etiqueta
            if ':' in line:
                label_part, instruction_part = line.split(':', 1)
                label = label_part.strip()
                self.labels[label] = self.current_address
                line = instruction_part.strip()
                
                # Si después de la etiqueta no hay instrucción, continuar
                if not line:
                    continue
            
            # Cada instrucción ocupa 4 bytes
            parts = line.replace(',', ' ').split()
            if parts and parts[0] in self.INSTRUCTION_TABLE:
                self.current_address += 4

    def decode(self, input_lines):
        """
        Decodifica una lista de líneas de ensamblador.
        Retorna una lista de strings binarios de 8 bits (bytes) para $readmemb.
        """
        # Primera pasada: recolectar etiquetas
        self.first_pass(input_lines)
        
        # Segunda pasada: generar código máquina
        output_bytes_str = []
        self.current_address = 0
        
        for i, line in enumerate(input_lines):
            line_num = i + 1
            original_line = line.strip()
            line = original_line.lower()
            
            if not line or line.startswith('#'):
                continue
            
            # Eliminar comentarios (todo después de #)
            if '#' in line:
                line = line.split('#')[0].strip()
                if not line:
                    continue
            
            # Manejar etiquetas
            if ':' in line:
                _, line = line.split(':', 1)
                line = line.strip()
                if not line:
                    continue
            
            parts = line.replace(',', ' ').split()
            
            mnemonic = parts[0]
            operands = parts[1:]
            
            if mnemonic not in self.INSTRUCTION_TABLE:
                raise ValueError(f"Línea {line_num}: Instrucción desconocida '{mnemonic}'")
            
            instr_info = self.INSTRUCTION_TABLE[mnemonic]
            
            try:
                machine_code = 0
                
                if instr_info['type'] == 'R':
                    machine_code = self.parse_r_type(operands, instr_info['funct'])
                    
                elif instr_info['type'] == 'I':
                    machine_code = self.parse_i_type(operands, instr_info['opcode'], instr_info)
                    
                elif instr_info['type'] == 'J':
                    machine_code = self.parse_j_type(operands, instr_info['opcode'])
                    
                else:
                    raise ValueError(f"Línea {line_num}: Tipo de instrucción '{instr_info['type']}' no soportado.")
                
                # Descomponer la instrucción de 32 bits en 4 bytes (Big Endian)
                byte0_str = f"{(machine_code >> 24) & 0xFF:08b}"
                byte1_str = f"{(machine_code >> 16) & 0xFF:08b}"
                byte2_str = f"{(machine_code >>  8) & 0xFF:08b}"
                byte3_str = f"{(machine_code >>  0) & 0xFF:08b}"
                
                output_bytes_str.append(byte0_str)
                output_bytes_str.append(byte1_str)
                output_bytes_str.append(byte2_str)
                output_bytes_str.append(byte3_str)
                
                self.current_address += 4

            except ValueError as e:
                raise ValueError(f"Línea {line_num} ('{original_line}'): {e}")
                
        return output_bytes_str


class MipsDecoderApp:
    """
    Crea la GUI con Tkinter para el decodificador MIPS.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Decodificador MIPS Completo - R/I/J Type")
        self.root.geometry("700x550")
        
        self.decoder = MipsDecoder()
        
        main_frame = tk.Frame(root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = tk.LabelFrame(main_frame, text="Código Ensamblador MIPS", padx=5, pady=5)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.text_input = scrolledtext.ScrolledText(input_frame, height=20, width=80, undo=True, font=("Courier", 10))
        self.text_input.pack(fill=tk.BOTH, expand=True)
        self.text_input.insert(tk.END, """# Decodificador MIPS - Soporta R-TYPE, I-TYPE y J-TYPE
# Ejemplos:

# R-TYPE
ADD $t0, $s0, $s1
SUB $t1, $t0, $t2
AND $s2, $s3, $s4
OR $a0, $a1, $a2
SLT $v0, $t3, $t4

# I-TYPE - Aritmética/Lógica
ADDI $t0, $zero, 10
ANDI $t1, $t0, 0xFF
ORI $s0, $zero, 0x1234
XORI $t2, $t1, 15
SLTI $v0, $t0, 100

# I-TYPE - Memoria
LW $t0, 0($sp)
SW $t1, 4($sp)
LW $s0, 100($t0)

# I-TYPE - Branch con etiquetas
loop:
    ADDI $t0, $t0, 1
    BEQ $t0, $t1, end
    J loop
end:
    ADD $v0, $zero, $t0
""")
        
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.btn_load_file = tk.Button(button_frame, text="📁 Cargar Archivo", command=self.load_file)
        self.btn_load_file.pack(side=tk.LEFT, padx=(0, 10))
        
        self.btn_decode_save = tk.Button(button_frame, text="⚙️ Decodificar y Guardar", 
                                         command=self.process_and_save, 
                                         font=("Helvetica", 10, "bold"),
                                         bg="#4CAF50", fg="white")
        self.btn_decode_save.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        info_frame = tk.LabelFrame(main_frame, text="Instrucciones Soportadas", padx=5, pady=5)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        info_text = """R-TYPE: ADD, SUB, AND, OR, SLT  |  I-TYPE: ADDI, ANDI, ORI, XORI, SLTI, BEQ, LW, SW  |  J-TYPE: J"""
        info_label = tk.Label(info_frame, text=info_text, justify=tk.LEFT, font=("Courier", 8))
        info_label.pack()
        
        status_frame = tk.Frame(main_frame)
        status_frame.pack(fill=tk.X)
        
        self.status_label = tk.Label(status_frame, text="Estado: Listo", bd=1, relief=tk.SUNKEN, anchor=tk.W, padx=5)
        self.status_label.pack(fill=tk.X)

    def update_status(self, message, color="black"):
        """Actualiza la etiqueta de estado."""
        self.status_label.config(text=f"Estado: {message}", fg=color)

    def load_file(self):
        """Abre un diálogo para seleccionar un archivo .txt y lo carga en el área de texto."""
        try:
            filepath = filedialog.askopenfilename(
                filetypes=[("Text files", "*.txt"), ("Assembly files", "*.asm"), ("All files", "*.*")],
                title="Seleccionar archivo de instrucciones"
            )
            if not filepath:
                return 
            
            with open(filepath, 'r') as f:
                content = f.read()
                
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", content)
            self.update_status(f"Archivo cargado: {filepath}", "blue")
            
        except Exception as e:
            messagebox.showerror("Error al Cargar", f"No se pudo leer el archivo:\n{e}")
            self.update_status(f"Error al cargar archivo: {e}", "red")

    def process_and_save(self):
        """
        Obtiene el texto, lo decodifica y lo guarda en un archivo .txt
        en formato binario de 8 bits por línea (para $readmemb).
        """
        input_text = self.text_input.get("1.0", tk.END)
        input_lines = input_text.splitlines()
        
        if not input_lines or all(not line.strip() or line.strip().startswith('#') for line in input_lines):
            messagebox.showwarning("Entrada Vacía", "No hay instrucciones para decodificar.")
            return

        try:
            # 1. Decodificar
            binary_strings = self.decoder.decode(input_lines)
            
            # 2. Pedir ubicación para guardar
            save_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile="Instrucciones.txt",
                filetypes=[("Text files (para Verilog)", "*.txt"), ("All files", "*.*")],
                title="Guardar archivo para $readmemb"
            )
            
            if not save_path:
                self.update_status("Guardado cancelado por el usuario.", "orange")
                return 
            
            # 3. Guardar el archivo
            with open(save_path, 'w') as f:
                for bin_str in binary_strings:
                    f.write(bin_str + '\n')
            
            num_instr = len(binary_strings) // 4
            num_labels = len(self.decoder.labels)
            
            label_info = f" ({num_labels} etiquetas detectadas)" if num_labels > 0 else ""
            
            self.update_status(f"¡Éxito! {num_instr} instrucciones → {save_path}{label_info}", "green")
            messagebox.showinfo("Éxito", 
                              f"✅ Archivo generado exitosamente\n\n"
                              f"📄 Archivo: {save_path}\n"
                              f"📊 Instrucciones: {num_instr}\n"
                              f"💾 Bytes: {len(binary_strings)}\n"
                              f"🏷️ Etiquetas: {num_labels}")

        except ValueError as e:
            messagebox.showerror("Error de Decodificación", f"❌ Ocurrió un error:\n\n{e}")
            self.update_status(f"Error: {e}", "red")
        except Exception as e:
            messagebox.showerror("Error Inesperado", f"❌ Ocurrió un error inesperado:\n\n{e}")
            self.update_status(f"Error inesperado: {e}", "red")


if __name__ == "__main__":
    root = tk.Tk()
    app = MipsDecoderApp(root)
    root.mainloop()