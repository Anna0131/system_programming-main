import sys

def is_valid_hex(s):
    """檢查是否為有效的十六進位數字"""
    try:
        int(s, 16)
        return all(c in '0123456789ABCDEFabcdef' for c in s)
    except ValueError:
        return False

def is_valid_decimal(s):
    """檢查是否為有效的十進位數字"""
    try:
        int(s)
        return True
    except ValueError:
        return False

def validate_byte_operand(operand):
    """驗證 BYTE 指令的運算元格式"""
    # operand 形如 X'F1' 或 C'EOF'
    if not operand or len(operand.split("'")) != 3:
        return False, "BYTE 指令格式錯誤 (應為 X'值' 或 C'值')"
    
    type_char, value, _ = operand.split("'")
    type_char = type_char.upper()
    if type_char == 'X':
        if not value or len(value) % 2 != 0:
            return False, "X'值' 中的十六進位數必須是偶數個數字"
        if not is_valid_hex(value):
            return False, f"X'值' 中含有非法的十六進位數字: {value}"
    elif type_char == 'C':
        if not value:
            return False, "C'值' 不能為空"
    else:
        return False, f"BYTE 指令的型態必須是 X 或 C，不能是 {type_char}"
    
    return True, None

def validate_word_operand(operand):
    """驗證 WORD 指令的運算元"""
    if not operand:
        return False, "程式碼格式錯誤 (缺少運算元)"
    try:
        int(operand)
        return True, None
    except ValueError:
        return False, f"WORD 指令的運算元必須是十進位數字，不能是 {operand}"

def validate_resw_operand(operand):
    """驗證 RESW 指令的運算元"""
    if not operand:
        return False, "程式碼格式錯誤 (缺少運算元)"
    try:
        int(operand)
        return True, None
    except ValueError:
        return False, f"RESW 指令的運算元必須是十進位數字，不能是 {operand}"

def validate_resb_operand(operand):
    """驗證 RESB 指令的運算元"""
    if not operand:
        return False, "程式碼格式錯誤 (缺少運算元)"
    try:
        int(operand)
        return True, None
    except ValueError:
        return False, f"RESB 指令的運算元必須是十進位數字，不能是 {operand}"

def validate_index_addressing(operand):
    """
    驗證索引定址格式，前後可能有空格，但一律先把逗號前後空格清掉。
    例如 "BUFFER ,X" 或 "BUFFER, X" 最後都轉為 "BUFFER,X" 處理。
    """
    if not operand:
        return False, "索引定址格式錯誤 (缺少運算元)"
    
    # 先把逗號前後空格去掉：https://stackoverflow.com/a/43582884
    operand_norm = operand.replace(" ", "")  # 把所有空格先去掉，就只剩 "BUFFER,X" 或純數字 etc.
    
    # 如果沒有逗號，就不是索引定址，直接視為可通過
    if ',' not in operand_norm:
        return True, None

    parts = operand_norm.split(',')
    if len(parts) != 2:
        return False, "索引定址格式錯誤 (太多逗號)"
    
    base_addr, index = parts
    if not base_addr:
        return False, "索引定址格式錯誤 (逗號前必須有運算元)"
    if index.upper() != 'X':
        return False, "索引定址格式錯誤 (逗號後只能接X)"
    return True, operand_norm  # 第二個回傳值改為「已經去空格+逗號處理過」的 operand_norm

# ===================================================================================
#                                     passOne
# ===================================================================================
def passOne(file_path, opcode_table):
    """
    passOne 會回傳：
      symbol_table:   { label: address_hex, ... }
      intermediate:   [[line_num, loc_hex, label, mnemonic, operand, opcode_hex, addressing], ...]
      operandConfirm: [[line_num, base_operand], ...]   （供 passTwo 檢查未定義符號）
      errorStatus:    [所有 passOne 時偵測到的錯誤訊息]
    """
    symbol_table = {}
    intermediate = []
    errorStatus = []
    operandConfirm = []  # 用來記錄「需要在 passTwo 再檢查是否已定義」的 operand

    firstIn = False
    firstCommand = True
    loc = [0, 0]   # loc[0] = 本行地址, loc[1] = 下一行地址
    special = {"START", "END", "WORD", "BYTE", "RESW", "RESB"}
    used_labels = set()

    with open(file_path, 'r') as file, open('109241047蔣馥安_passOne_output.txt', 'w') as PassOne_output_file:
        for num, raw_line in enumerate(file, start=1):
            line = raw_line.rstrip('\n')
            parts = []

            # 忽略全空白或以 '.' 開頭的註解
            if not line.strip() or line.strip().startswith('.'):
                continue

            # 去掉行內註解
            if '.' in line:
                line = line.split('.', 1)[0].rstrip()
                if not line:
                    continue

            # 先按空白 split
            parts = line.strip().split()

            # ---------------------------
            # 先判斷「第一個 token 是 MNEMONIC 還是 LABEL」
            # 若 parts[0] 在 opcode_table 或 special 或 == "RSUB"，就把它當作 mnemonic
            # 否則就假設 parts[0] 是 label，parts[1] 要在 opcode_table 或 special 或 == "RSUB"
            # ---------------------------
            label = '***'
            mnemonic = '***'
            operand = '***'
            opcode_hex = ''
            addressing = 'direct'

            # 把所有 token 先轉成大寫比對，但保留原始大小寫以免 literal 出錯
            upper0 = parts[0].upper()
            if upper0 in opcode_table or upper0 in special or upper0 == "RSUB":
                # 第一個就是 mnemonic
                label = '***'
                mnemonic = upper0
                if len(parts) > 1:
                    operand = " ".join(parts[1:]).strip()
                else:
                    operand = '***'
            else:
                # parts[0] 當作 label，看 parts[1]
                if len(parts) >= 2:
                    upper1 = parts[1].upper()
                    if upper1 in opcode_table or upper1 in special or upper1 == "RSUB":
                        label = parts[0]
                        mnemonic = upper1
                        if len(parts) > 2:
                            operand = " ".join(parts[2:]).strip()
                        else:
                            operand = '***'
                    else:
                        # 既不是「第一個是 mnemonic」，也不是「第二個是 mnemonic」，視為 label-only 但下一行才接指令
                        # 把這個 label 記起來，暫時不把它存 symbol_table，等下一次真有 mnemonic 才補上
                        # 我們先把 num 跟 label 存進 intermediate，loc 先留空
                        # 但為了你的錯誤檢查流，我這裡直接略過這一行
                        # 你可以根據需要再決定要不要把 label-only 這種情況「暫存」起來
                        errorStatus.append(f"無效的 Opcode ({parts[0]}) in line : {num}")
                        continue
                else:
                    # 只有一個 token，但又不在 opcode_table 裡，視為「無效指令」
                    # 直接報錯、略過
                    errorStatus.append(f"無效的指令 ({parts[0]}) in line : {num}")
                    continue

            # 標記第一次進入指令，之後就不是第一行
            if firstIn:
                firstCommand = False
            firstIn = True

            # ---------------------------
            # 處理第一條必須是 START
            # ---------------------------
            if firstCommand:
                if mnemonic != "START" or operand == '***':
                    errorStatus.append(f"程式必須以 START 指令開始 in line : {num}")
                    continue

                # 檢查 START operand 是否為合法十六進位
                if not is_valid_hex(operand):
                    errorStatus.append(f"START 指令的位址必須是有效的十六進位數，而不是 {operand} in line : {num}")
                    continue

                loc[0] = int(operand, 16)
                loc[1] = loc[0]
                firstCommand = False

                # 如果有 label，就把 label 記到 symbol_table
                if label != '***':
                    if label in symbol_table:
                        errorStatus.append(f"重複定義的標籤 {label} in line : {num}")
                    else:
                        symbol_table[label] = f"{loc[0]:04X}"

                # 寫 intermediate：opcode_hex 用 '***' 佔位
                intermediate.append([str(num), f"{loc[0]:04X}", label, "START", operand, "***", addressing])
                continue

            # ---------------------------
            # 檢查 label 重複
            # ---------------------------
            if label != '***':
                if label in symbol_table:
                    errorStatus.append(f"重複定義的標籤 {label} in line : {num}")
                else:
                    symbol_table[label] = f"{loc[0]:04X}"

            # ---------------------------
            # 檢查無效的 mnemonic
            # ---------------------------
            if mnemonic not in opcode_table and mnemonic not in {"START", "END", "BYTE", "WORD", "RESW", "RESB", "RSUB"}:
                errorStatus.append(f"無效的指令 ({mnemonic}) in line : {num}")

            # ---------------------------
            # 處理 END (還要檢查是否有 operand)
            # ---------------------------
            if mnemonic == "END":
                if operand == '***':
                    errorStatus.append(f"程式碼格式錯誤 (缺少運算元) in line : {num}")
                intermediate.append([str(num), f"{loc[0]:04X}", label, "END", operand, "***", addressing])
                operandConfirm.append([num, operand])
                continue

            # ---------------------------
            # 處理 RSUB：不該帶 operand
            # ---------------------------
            if mnemonic == "RSUB":
                if operand != '***':
                    errorStatus.append(f"RSUB 指令不應該有運算元 in line : {num}")
                opcode_hex = opcode_table.get("RSUB", "4C")
                intermediate.append([str(num), f"{loc[0]:04X}", label, "RSUB", "***", opcode_hex, addressing])
                loc[1] = loc[0] + 3
                loc[0] = loc[1]
                continue

            # ---------------------------
            # 處理 BYTE / WORD / RESW / RESB
            # ---------------------------
            if mnemonic == "BYTE":
                valid, msg = validate_byte_operand(operand)
                if not valid:
                    errorStatus.append(f"{msg} in line : {num}")
                    size = 0
                else:
                    # C'...' 佔 len(...) bytes，X'...' 佔 len(...)//2 bytes
                    if operand.upper().startswith("C'"):
                        size = len(operand[2:-1])
                    else:
                        size = len(operand[2:-1]) // 2
                intermediate.append([str(num), f"{loc[0]:04X}", label, "BYTE", operand, "***", addressing])
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            if mnemonic == "WORD":
                valid, msg = validate_word_operand(operand)
                if not valid:
                    errorStatus.append(f"{msg} in line : {num}")
                    size = 0
                else:
                    size = 3
                intermediate.append([str(num), f"{loc[0]:04X}", label, "WORD", operand, "00", addressing])
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            if mnemonic == "RESW":
                valid, msg = validate_resw_operand(operand)
                if not valid:
                    errorStatus.append(f"{msg} in line : {num}")
                    size = 0
                else:
                    size = 3 * int(operand)
                intermediate.append([str(num), f"{loc[0]:04X}", label, "RESW", operand, "***", addressing])
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            if mnemonic == "RESB":
                valid, msg = validate_resb_operand(operand)
                if not valid:
                    errorStatus.append(f"{msg} in line : {num}")
                    size = 0
                else:
                    size = int(operand)
                intermediate.append([str(num), f"{loc[0]:04X}", label, "RESB", operand, "***", addressing])
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            # ---------------------------
            # 處理「可能有逗號」的一般指令
            # 先把逗號前後空格移除，在判 index addressing
            # ---------------------------
            base_operand = operand  # 原始
            is_indexed = False

            if operand != '***' and ',' in operand:
                valid_idx, normalized = validate_index_addressing(operand)
                if not valid_idx:
                    errorStatus.append(f"{normalized} in line : {num}" if "索引定址格式錯誤" in normalized else f"{normalized} in line : {num}")
                    # 格式錯就先塞進 intermediate，再跳下一行
                    intermediate.append([str(num), f"{loc[0]:04X}", label, mnemonic, operand, "***", addressing])
                    continue
                else:
                    # normalized 已經把空格都去掉了 e.g. "BUFFER,X"
                    base_operand = normalized
                    is_indexed = True
                    addressing = "indexed"

            # 一般 mnemonic in opcode_table，size=3
            if mnemonic in opcode_table:
                opcode_hex = opcode_table[mnemonic]
                size = 3

                # 若 base_operand 不是純數字，也不是含 "'"，就要留到 passTwo 再檢查 symbol
                if base_operand != '***' \
                   and not is_valid_decimal(base_operand) \
                   and ("'" not in base_operand):
                    operandConfirm.append([num, base_operand])

                intermediate.append([str(num), f"{loc[0]:04X}", label, mnemonic, base_operand, opcode_hex, addressing])
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            # 如果走到這裡，代表「mnemonic 既不在 opcode_table，也不是上述特殊指令」，我們就先把它塞到 intermediate
            intermediate.append([str(num), f"{loc[0]:04X}", label, mnemonic, operand, "***", addressing])
            # loc[0] 保持不變

        # passOne 最後，確認至少有 START/END
        if not any(r[3] == "START" for r in intermediate):
            errorStatus.append("程式必須以 START 指令開始")
        if not any(r[3] == "END" for r in intermediate):
            errorStatus.append("程式必須以 END 指令結束")

        # 把 intermediate 全部寫進檔案
        for row in intermediate:
            PassOne_output_file.write(" ".join(row) + "\n")

        return symbol_table, intermediate, operandConfirm, errorStatus

# ===================================================================================
#                                     passTwo
# ===================================================================================
def passTwo(symbol_table, intermediate, operandConfirm):
    """
    passTwo 僅做「找不到 symbol」的檢查，
    如果所有 operandConfirm 中的 base_operand 不在 symbol_table，就報錯。
    """
    errors2 = []
    for ln, sym in operandConfirm:
        # split the sym to get the label if it is indexed addressing
        if ',' in sym:
            sym = sym.split(',')[0]
        if sym not in symbol_table:
            errors2.append(f"[passTwo] 錯誤：第 {ln} 行使用了未定義的符號 {sym}。")

    if errors2:
        print("==== passTwo 發現的錯誤 ====")
        for e in errors2:
            print(e)
        sys.exit(1)

    # 如果要繼續組物件碼 H/T/E，就在這裡接續；本範例只示範「未定義符號檢查」到此結束
    print("==== passTwo 沒有發現未定義符號，後續可做物件碼組合 ====")

# ===================================================================================
#                                      Main
# ===================================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 SIC_twoPass.py <source_file>")
        sys.exit(1)

    source_file = sys.argv[1]

    # 先建立 opcode_table，請確保 opCode.txt 和本程式在同一資料夾
    opcode_table = {}
    try:
        with open("opCode.txt", 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    mnem = parts[0].upper()
                    code = parts[1].upper()
                    opcode_table[mnem] = code
    except FileNotFoundError:
        print("找不到 opCode.txt，請放在相同目錄下")
        sys.exit(1)

    # passOne
    symbol_table, intermediate, operandConfirm, pass1_errors = passOne(source_file, opcode_table)

    # 不論 passOne 有無錯，都先把 pass1_errors 列出來
    if pass1_errors:
        print("==== passOne 發現的錯誤 ====")
        for e in pass1_errors:
            print(e)

    # 再執行 passTwo，一次檢查所有未定義符號
    passTwo(symbol_table, intermediate, operandConfirm)

    # 若到這裡都沒 exit，表示 passTwo 也沒找到「使用未定義符號」
    # （後續才可以做真正的物件碼組合 H/T/E，如果需要就自行加上去）