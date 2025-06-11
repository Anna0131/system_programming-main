import sys

# 全域變數，用於存儲程式的起始和結束位址
program_start_address = 0
program_end_address = 0
program_end_loc = 0  # 專門存儲 END 指令的位置
program_length = 0   # 程式長度

def is_valid_hex(s):
    """檢查是否為有效的十六進位數字"""
    try:
        int(s, 16) # 嘗試將字串轉換為十六進位數字
        return all(c in '0123456789ABCDEFabcdef' for c in s) # 確認所有字元都是合法的十六進位數字
    except ValueError:
        return False

def is_valid_decimal(s):
    """檢查是否為有效的十進位數字"""
    try:
        int(s) # 嘗試將字串轉換為十進位數字
        return True
    except ValueError:
        return False

def validate_byte_operand(operand):
    """驗證 BYTE 指令的運算元格式"""
    # 檢查 operand 是否符合 X'F1' 或 C'EOF' 格式
    if not operand or len(operand.split("'")) != 3:
        return False, "BYTE 指令格式錯誤 (應為 X'值' 或 C'值')"
    # not operand：如果 operand 是空字串或 None，視為格式錯誤。
    # 第 0 塊：型態字元（"X" 或 "C")/第 1 塊：中間的資料（十六進位或字元串）/第 2 塊：切割後尾端的空字串'    
    type_char, value, _ = operand.split("'")
    type_char = type_char.upper()# 將型態字元轉成大寫，方便比較
    
    # 處理十六進位格式
    if type_char == 'X':
        # 先判斷內容是否為空白格子  
        value = value.strip() 
        if not value:
            return False, "X'值' 不能為空白"
        if not value or len(value) % 2 != 0: #十六進位兩個字元才代表一個 byte，所以長度必須是偶數。
            return False, "X'值' 中的十六進位數必須是偶數個數字"
        if not is_valid_hex(value): #呼叫外部函式，確保每一個字元都在 0-9、A-F 範圍內
            return False, f"X'值' 中含有非法的十六進位數字: {value}"
    
    # 處理字元格式
    elif type_char == 'C':
        if not value: #只要確保中間 value 裡至少有一個字元
            return False, "C'值' 不能為空"
    else:
        return False, f"BYTE 指令的型態必須是 X 或 C，不能是 {type_char}"
    
    return True, None #合法且沒有錯誤訊息回 (True, None)，不合法回 (False, <錯誤訊息>)。

# 記憶體配置指令驗證
def validate_word_operand(operand):
    """驗證 WORD 指令的運算元"""
    if not operand: # WORD指令必須有運算元
        return False, "程式碼格式錯誤 (缺少運算元)"
    try:
        int(operand) # 嘗試將字串轉換為十進位數字 ，如果成功，回傳 True 和 None
        return True, None 
    except ValueError:
        return False, f"WORD 指令的運算元必須是十進位數字，不能是 {operand}"

def validate_resw_operand(operand):
    """驗證 RESW 指令，必須有運算元且為十進位數字"""
    if not operand:
        return False, "程式碼格式錯誤 (缺少運算元)"
    try:
        int(operand)
        return True, None
    except ValueError:
        return False, f"RESW 指令的運算元必須是十進位數字，不能是 {operand}"

def validate_resb_operand(operand):
    """驗證 RESB 指令，必須有運算元且為十進位數字"""
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
    
    # 檢查索引定址格式，有逗號，且只有一個逗號
    parts = operand_norm.split(',')
    if len(parts) != 2:
        return False, "索引定址格式錯誤 (太多逗號)"
    
    base_addr, index = parts # 把 operand_norm 用逗號拆成兩部分，base_addr 是第一部分，index 是第二部分
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
    global program_start_address, program_end_address, program_end_loc, program_length  # 使用全域變數
    
    symbol_table = {}# 符號表：{標籤: 十六進位位址}
    intermediate = []# 中間檔：[[行號, 位址, 標籤, 指令, 運算元, 指令碼, 定址方式], ...]
    errorStatus = []# 錯誤訊息：[所有 passOne 時偵測到的錯誤訊息]
    operandConfirm = []  # 待確認的 operand：[行號, 運算元]

    firstIn = False # 是否是第一行(是否已經開始處理指令)
    firstCommand = True # 是否是第一條指令
    loc = [0, 0]   # 位置計數器：[當前位址,下一個位址]
    special = {"START", "END", "WORD", "BYTE", "RESW", "RESB"}#特殊指令集
    used_labels = set()# 已使用過的label

    with open(file_path, 'r') as file, open('passOne_output.txt', 'w') as PassOne_output_file:
        for num, raw_line in enumerate(file, start=1): 
        # enumerate是一個內建函式，會把可迭代物件（這裡是 file）每個元素「打包」成 (index, element) 形式，依序回傳。
        # num：會依序是 1、2、3…，代表當前讀到的行號。raw_line：是 file 第 num 行的原始文字（包含「\n」）。            
            line = raw_line.rstrip('\n') # 移除換行符
            parts = [] # 存分割後的token

            # 忽略該行全空白或以 '.' 開頭的註解
            if not line.strip() or line.strip().startswith('.'):
                continue

            # 去掉行內註解
            if '.' in line:
                line = line.split('.', 1)[0].rstrip() #以第一個 . 為切割點，取左邊那段（程式碼部份）。
                if not line: #如果去掉註解和空白之後變空，那行就不用處理了
                    continue

            # 按空白分割指令，但保留BYTE指令中的空格
            line = line.strip()
            if "BYTE" in line and ("C'" in line or "X'" in line):
                # 先正常分割取得基本部分
                parts = line.split()
                # 找到BYTE指令的位置
                byte_index = -1
                for i, part in enumerate(parts):
                    if part == "BYTE":
                        byte_index = i
                        break
                # 如果找到BYTE，重新處理其operand
                if byte_index >= 0 and byte_index + 1 < len(parts):
                    operand_part = line.split("BYTE", 1)[1].strip()
                    parts = parts[:byte_index + 1]  # 保留到BYTE
                    parts.append(operand_part)  # 加入完整operand
            else:
                # 先用空格分割
                parts = line.split()
                
                # 檢查是否有索引定址（包含逗號的情況）
                if len(parts) >= 2:  # 至少要有兩個部分才可能有索引定址
                    # 檢查最後兩個部分是否包含逗號
                    last_parts = ' '.join(parts[-2:])  # 合併最後兩個部分
                    if ',' in last_parts:  # 如果包含逗號
                        # 重新處理，保留前面的部分，並將最後帶有逗號的部分合併
                        base_parts = parts[:-2]  # 前面的部分
                        base_parts.append(last_parts)  # 加入合併後的最後部分
                        parts = base_parts

            # 檢查欄位數量
            if len(parts) > 3:
                errorStatus.append(f"欄位數量超過限制 in line : {num}")
                continue

            # ---------------------------
            # 先判斷「第一個 token 是 MNEMONIC 還是 LABEL」
            # 若 parts[0] 屬於 opcode_table 或 special 或 == "RSUB"，就把它當作 mnemonic
            # 否則就假設 parts[0] 是 label，parts[1] 要在 opcode_table 或 special 或 == "RSUB"
            # ---------------------------
            label = '***'
            mnemonic = '***'
            operand = '***'
            opcode_hex = ''
            addressing = 'direct'

            # 把所有 token 先轉成大寫比對，但保留原始大小寫以免 literal 出錯
            upper0 = parts[0].upper() # 第一個token的大寫

            if upper0 in opcode_table or upper0 in special or upper0 == "RSUB":# 第一個就是 mnemonic
                label = '***'
                mnemonic = upper0 #如果第一個 token 本身就是已知指令，就把它當作 mnemonic
                
                # 檢查欄位數量
                if len(parts) > 2:
                    errorStatus.append(f"欄位數量超過限制 in line : {num}")
                    continue
                
                if len(parts) > 1:
                    # 檢查運算元是否為指令
                    operand_upper = parts[1].upper()
                    if operand_upper in opcode_table or operand_upper in special or operand_upper == "RSUB":
                        errorStatus.append(f"運算元不可以是指令 in line : {num}")
                        continue
                    operand = parts[1]  # 直接使用第二個token作為operand
                else:
                    if mnemonic != "RSUB":  # RSUB不需要運算元
                        errorStatus.append(f"指令缺少運算元 in line : {num}")
                        continue
                    operand = '***'
                
            else: 
                # parts[0] 當作 label，看 parts[1]
                if len(parts) > 1:
                    upper1 = parts[1].upper()
                    if upper1 in opcode_table or upper1 in special or upper1 == "RSUB":
                        label = parts[0]
                        mnemonic = upper1
                        # 檢查欄位數量
                        if len(parts) > 3:
                            errorStatus.append(f"欄位數量超過限制 in line : {num}")
                            continue
                        
                        if len(parts) > 2:
                            # 檢查運算元是否為指令
                            operand_upper = parts[2].upper()
                            if operand_upper in opcode_table or operand_upper in special or operand_upper == "RSUB":
                                errorStatus.append(f"運算元不可以是指令 in line : {num}")
                                continue
                            operand = parts[2]  # 直接使用第三個token作為operand
                        else:
                            if mnemonic != "RSUB":  # RSUB不需要運算元
                                errorStatus.append(f"指令缺少運算元 in line : {num}")
                                continue
                            operand = '***'
                    else:
                        # 既不是「第一個是 mnemonic」，也不是「第二個是 mnemonic」，視為 label-only 但下一行才接指令
                        # 把這個 label 記起來，暫時不把它存 symbol_table，等下一次真有 mnemonic 才補上
                        # 我們先把 num 跟 label 存進 intermediate，loc 先留空
                        # 但為了錯誤檢查流，我這裡直接略過這一行
                        errorStatus.append(f"無效的 Opcode ({parts[0]}) in line : {num}")
                        continue
                else:
                    # 只有一個 token，但又不在 opcode_table 裡，視為「無效指令」
                    # 直接報錯、略過
                    errorStatus.append(f"無效的指令 ({parts[0]}) in line : {num}")
                    continue

            # 標記第一次進入指令，之後就不是第一行
            if firstIn:
                firstCommand = False # 標記不是第一條指令
            firstIn = True # 已經進入指令

            # ---------------------------
            # 處理第一條必須是 START
            # ---------------------------
            if firstCommand: # 第一條指令(代表還沒碰過任何真正的指令)
                if mnemonic != "START" or operand == '***': #operand == '***'：或是 START 後面根本沒有看到運算元
                    errorStatus.append(f"程式必須以 START 指令開始 in line : {num}")
                    continue

                # 檢查 START 的 operand 是否為合法十六進位
                if not is_valid_hex(operand):
                    errorStatus.append(f"START 指令的位址必須是有效的十六進位數，而不是 {operand} in line : {num}")
                    continue

                #設定位置計數器
                loc[0] = int(operand, 16)
                loc[1] = loc[0]
                program_start_address = loc[0]  # 記錄程式起始位址
                firstCommand = False # 代表「已經處理過 START」，之後就不會再進來這個區塊了

                # 如果有 label，就把 label 記到 symbol_table
                if label != '***':
                    if label in symbol_table: #如果在 symbol_table 已經見過同樣的 label
                        errorStatus.append(f"重複定義的標籤 {label} in line : {num}")
                    else:
                        symbol_table[label] = f"{loc[0]:04X}" #把 label => loc[0] （起始位址）放入符號表。
                        # X 表示要把整數當做十六進位輸出，且字母用大寫（A-F）。
                        # 4 表示寬度至少 4 個字元。
                        # 0 表示如果不足 4 位，就在左邊補 0。

                # 寫 intermediate：opcode_hex 用 '***' 佔位
                intermediate.append([str(num), f"{loc[0]:04X}", label, "START", operand, "***", addressing])
                continue
                # [行號,4位十六進位的位址,label,指令,運算元,opcode_hex 佔位(因為 START 不會產生機械碼),定址方式]

            # Pass 1 中，對每一行中間檔的封裝前，做一些「結構性檢查」和「特殊指令處理」。
            # ---------------------------
            # 檢查 label 重複
            # ---------------------------
            if label != '***': #實際有定義一個 Label
                if label in symbol_table:
                    errorStatus.append(f"重複定義的標籤 {label} in line : {num}")
                else:
                    symbol_table[label] = f"{loc[0]:04X}"
                    # 在 Pass 1 時，一旦看到某個標籤，就把它記下來；若同一個標籤出現第二次，就馬上報錯，防止以後生成 object code 時地址對不上。
            # ---------------------------
            # 檢查無效的 mnemonic
            # ---------------------------
            # 既不是一般機器指令,也不是組譯器專用的偽指令,或特殊機器指令 RSUB
            if mnemonic not in opcode_table and mnemonic not in {"START", "END", "BYTE", "WORD", "RESW", "RESB", "RSUB"}:
                errorStatus.append(f"無效的指令 ({mnemonic}) in line : {num}")
                continue

            # ---------------------------
            # 處理 END (還要檢查是否有 operand)
            # ---------------------------
            if mnemonic == "END":
                if operand == '***': #檢查 operand：END 必須跟一個label或位址
                    errorStatus.append(f"程式碼格式錯誤 (缺少運算元) in line : {num}")
                intermediate.append([str(num), f"{loc[0]:04X}", label, "END", operand, "***", addressing])
                operandConfirm.append([num, operand]) #把 operand 加到 operandConfirm：稍後 Pass 2 要檢查它在符號表中是否定義過。
                program_end_loc = loc[0]  # 記錄 END 指令的位置
                continue
                # END 這類不產生物件碼的偽指令，必須記錄在中間檔並保留 operand，之後再檢查那個 Entry point 是否正確。

            # ---------------------------
            # 處理 RSUB ,這類特殊機器指令，不帶 operand、固定 3 bytes
            # ---------------------------
            if mnemonic == "RSUB":
                if operand != '***':
                    errorStatus.append(f"RSUB 指令不應該有運算元 in line : {num}")
                opcode_hex = opcode_table.get("RSUB", "4C") #從 opcode_table 拿 RSUB 的 opcode 塞進 opcode_hex。
                intermediate.append([str(num), f"{loc[0]:04X}", label, "RSUB", "***", opcode_hex, addressing])
                loc[1] = loc[0] + 3 # RSUB 是 3 bytes，所以 loc[1] = loc[0] + 3
                loc[0] = loc[1] # 把 loc[0] 設成 loc[1]，準備下一行計算地址。
                continue

            # ---------------------------
            # 處理 BYTE / WORD / RESW / RESB
            # ---------------------------
            if mnemonic == "BYTE":
                valid, msg = validate_byte_operand(operand) #驗證 BYTE 指令的運算元格式：是X'偶數個16進位數字'或C'...'，且內容不能為空
                if not valid: #BYTE指令格式不對
                    errorStatus.append(f"{msg} in line : {num}")
                    size = 0 #後面不移動 LOCCTR
                else:
                    # C'...' 佔 len(...) bytes，
                    # X'...' 佔 len(...)//2 bytes
                    if operand.upper().startswith("C'"): #合法時，先判斷它是 C 型（字串型）：
                        content = operand[2:-1]  # Remove C' and '，取出單引號之間的字串，例如 C'HELLO' 就得到 "HELLO"。
                        size = len(content) #每個字元佔 1 byte
                        # For long character strings, we need to create multiple intermediate entries
                        if size > 30:  # 分段處理超過 30 bytes 的 C 字串
                            chunks = [content[i:i+30] for i in range(0, len(content), 30)] 
                            #因為一條 Text Record 最多只能放 30 bytes；如果 content 太長，就先每 30 字一段切開。
                            #range(start, stop, step) 會產生從 start 開始，到（但不包括）stop，每次遞增 step 的整數序列。(ex:0, 30, 60, 90)
                            # [content[0:30], content[30:60],content[60:90], … ]
                            for i, chunk in enumerate(chunks): # enumerate 會給每個 chunk 一個索引號 i，從0開始
                                if i == 0:
                                    # 第一個片段,保留原始的label
                                    intermediate.append([str(num), f"{loc[0]:04X}", label, "BYTE", f"C'{chunk}'", "***", addressing]) 
                                    #創建新的 BYTE 指令，格式為 C'chunk'
                                else:
                                    # 後續片段，不保留 label(因為同一個標籤不能重複使用)
                                    intermediate.append([str(num), f"{loc[0]:04X}", "***", "BYTE", f"C'{chunk}'", "***", addressing])
                                loc[1] = loc[0] + len(chunk) #計算下一個指令的位址(每個字符佔用1 byte，所以增加的量就是 chunk 的長度)
                                loc[0] = loc[1] #更新為新的當前位址
                            continue
                    else:  # 非 C，就一定是 X 型
                        hex_content = operand[2:-1]  # Remove X' and ',取出單引號中間的十六進位字串。
                        size = len(hex_content) // 2 # 每兩個 hex 數字佔 1 byte     
                        if size > 30:  # 同樣，如果超過 30 bytes（也就是超過 60 個 hex 字元），就每 60 個 hex 字元一段切，並分開輸出多行中間檔。
                            chunks = [hex_content[i:i+60] for i in range(0, len(hex_content), 60)]  # 60 hex chars = 30 bytes
                            for i, chunk in enumerate(chunks):
                                if i == 0:
                                    # First chunk uses original location
                                    intermediate.append([str(num), f"{loc[0]:04X}", label, "BYTE", f"X'{chunk}'", "***", addressing])
                                else:
                                    # Subsequent chunks use new locations and no label
                                    intermediate.append([str(num), f"{loc[0]:04X}", "***", "BYTE", f"X'{chunk}'", "***", addressing])
                                loc[1] = loc[0] + len(chunk) // 2 # 每兩個 hex 數字佔 1 byte   
                                loc[0] = loc[1]
                            continue
                    
                # For normal length BYTE instructions
                intermediate.append([str(num), f"{loc[0]:04X}", label, "BYTE", operand, "***", addressing])
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            #固定 3 bytes，對應放一個整數常數。
            if mnemonic == "WORD":
                valid, msg = validate_word_operand(operand) #驗證 WORD 指令的運算元，必須能轉換為十進位數字,且不能為空
                if not valid:
                    errorStatus.append(f"{msg} in line : {num}")
                    size = 0 #後面不移動 LOCCTR
                else:
                    size = 3 # WORD 指令固定 3 bytes
                intermediate.append([str(num), f"{loc[0]:04X}", label, "WORD", operand, "00", addressing]) 
                # WORD n 在 Pass 2 的時候，會被翻成「00xxxx」這樣的 3 字元組機器碼：
                # 前面一個 byte（2 個 hex）固定是 00，後面 2 個 byte（4 個 hex）是那個十進位整數的 hex。因此在中間檔直接把這個「機器碼最前面那個 byte」預先指定為 "00"，方便 Pass 2 看到 opcode_hex == "00" 就知道要把它串成真正的 object code。                
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            # 保留 n 個 word    
            if mnemonic == "RESW":
                valid, msg = validate_resw_operand(operand) #驗證 RESW 指令的運算元，必須能轉換為十進位數字,且不能為空
                if not valid:
                    errorStatus.append(f"{msg} in line : {num}")
                    size = 0 
                else:
                    size = 3 * int(operand) # 每個 RESW 佔 3 bytes
                intermediate.append([str(num), f"{loc[0]:04X}", label, "RESW", operand, "***", addressing])
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue

            #保留 n 個 byte。
            if mnemonic == "RESB":
                valid, msg = validate_resb_operand(operand) #驗證 RESB 指令的運算元，必須能轉換為十進位數字,且不能為空
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
            # 處理「可能有逗號」的一般指令，先把逗號前後空格移除，再判 index addressing
            # ---------------------------
            # 先偵測 operand 裡有沒有逗號，處理索引定址
            base_operand = operand  # 暫存要實際使用的 operand，一開始就設成原始值。
            is_indexed = False #之後若檢測到有索引定址就設 True。
            # 處理「一般指令」（非 START/END/BYTE/WORD/RESW/RESB/RSUB）並支援索引定址（,）
            if operand != '***' and ',' in operand: #當 operand 不是佔位 *** 且字串內含逗號才處理。
                valid_idx, normalized = validate_index_addressing(operand) #會去除多餘空格，確認格式合法（只有一個逗號、逗號後是 X），並回傳 (True, "BUFFER,X") 或 (False, 錯誤訊息).
                if not valid_idx: # 格式錯
                    errorStatus.append(f"{normalized} in line : {num}" if "索引定址格式錯誤" in normalized else f"{normalized} in line : {num}")
                    # 格式錯就把這行「照原樣」先塞進中間檔（opcode_hex 用 *** 佔位），再跳下一行
                    intermediate.append([str(num), f"{loc[0]:04X}", label, mnemonic, operand, "***", addressing])
                    continue
                else: #格式對
                    # normalized 已經把空格都去掉了 ex: "BUFFER,X"
                    base_operand = normalized
                    is_indexed = True
                    addressing = "indexed" #代表這行指令在後面要生成索引定址的機器碼。

            # 如果 mnemonic 在 opcode_table 裡，就知道是普通的 Format-3 指令，固定 3 bytes
            # 就把 opcode、operand（已去空格）放中間檔，LOCCTR +=3
            if mnemonic in opcode_table:
                opcode_hex = opcode_table[mnemonic] #讀出它對應的兩位 hex，例如 ADD→18。
                size = 3
                # 當 base_operand 不是空 (***)、也不是一個純十進位數字、也不是 literal ('…')，就要留到 passTwo 檢查 label 到底在不在 symbol_table 裡。
                if base_operand != '***' \
                   and not is_valid_decimal(base_operand) \
                   and ("'" not in base_operand):
                    operandConfirm.append([num, base_operand])
                
                # 是 literal('…') 或 純數字，就塞進中間檔，LOCCTR +=3
                intermediate.append([str(num), f"{loc[0]:04X}", label, mnemonic, base_operand, opcode_hex, addressing])
                #base_operand:已正規化的 operand，例如 "BUFFER,X" 或 "BUFFER"。
                loc[1] = loc[0] + size
                loc[0] = loc[1]
                continue #處理完這行就跳過下面最後的「catch-all」區塊。

            # Catch-All 區塊
            # 走到這裡代表「mnemonic 不在 opcode_table，也不是特殊指令(BYTE/WORD/RESW/RESB/RSUB)」，故把這行原樣輸出到中間檔，用 *** 佔 opcode_hex。
            intermediate.append([str(num), f"{loc[0]:04X}", label, mnemonic, operand, "***", addressing])
            # loc[0] 保持不變,不更新 （因為格式錯誤或根本不是指令的行，不影響位址流）。
            # 如此 Pass 1 能把所有「有逗號的一般指令」和「不合法指令」都記錄在 intermediate，並為 Pass 2 預留資料檢查和機器碼生成所需的各種欄位。

            # 每次更新位址時，同時更新結束位址
            if mnemonic == "END":
                program_end_loc = loc[0]  # 記錄 END 指令的位置
            # 更新最後一個指令的位址（不包含 END 指令）
            if mnemonic != "END" and loc[0] > program_end_address:
                program_end_address = loc[0]

        # passOne 最後，確認至少有 START/END
        if not any(r[3] == "START" for r in intermediate):
            errorStatus.append("程式必須以 START 指令開始")
        if not any(r[3] == "END" for r in intermediate):
            errorStatus.append("程式必須以 END 指令結束")

        # 計算程式長度（最後一個指令的位址 - 起始位址）
        if program_end_address > program_start_address:
            program_length = program_end_address - program_start_address
        else:
            # 如果沒有找到有效的結束位址，使用 END 指令的位置
            program_length = program_end_loc - program_start_address

        # 把 intermediate 全部寫進檔案
        for row in intermediate:
            PassOne_output_file.write(" ".join(row) + "\n")

        print("\n==== Program Information ====")
        print(f"Start Address: {program_start_address:04X}")
        print(f"End Address: {program_end_address:04X}")  # 最後一個指令的位址
        print(f"End Location: {program_end_loc:04X}")    # END 指令的位置
        print(f"Program Length: {program_length:04X}")    # 程式長度（用於 H record）
        print("-" * 30)

        return symbol_table, intermediate, operandConfirm, errorStatus
        # symbol_table：Pass 1 建好的標籤→位址對照表。 { label: address_hex, ... }
        # intermediate：中間檔，用於讓 Pass 2 生成 Object Code。 [[line_num, loc_hex, label, mnemonic, operand, opcode_hex, addressing], ...]
        # operandConfirm：紀錄所有 operand 中看起來像符號（在symbol_table 裡已定義的label），需要在 Pass 2 去 symbol_table 裡確認的清單。[[line_num, base_operand], ...]
        # errorStatus：所有在 Pass 1 發現的錯誤訊息，Pass 2 可以繼續補檢符號之後一次印完。

        # 符號（symbol）就是那些「已定義的label」，會被存到 symbol_table 中。 key 是 label 名稱，value 是它的位址。
        # 操作數（operand）指的是 指令後面跟的那一塊字串，比如 LDA BUFFER,X 中的 BUFFER,X，或 JEQ LOOP 中的 LOOP。


# ===================================================================================
#                                     passTwo
# ===================================================================================
def generate_object_code(operand, opcode, symbol_table, addressing):
    #根據「操作數 operand」、「助記符(（mnemonic）ex:LDA)的 Opcode」、「符號表 symbol_table」和「定址方式 addressing」產生該行的object code
    """Generate object code for an instruction"""
    if opcode == '***': #代表這行在 Pass 1 已經標成不產生機械碼的偽指令（通常是 BYTE、RESW、RESB，或是格式錯誤都會佔用這個佔位）。
        # Special handling for BYTE instruction
        if operand.startswith("C'") and operand.endswith("'"):  # Character literal
            chars = operand[2:-1]  # Remove C' and '
            return ''.join([f"{ord(c):02X}" for c in chars]) # 把每個字元的 ASCII 轉成兩位十六進位，串起來。例如 C'AB' → ['41','42'] → "4142"。
        elif operand.startswith("X'") and operand.endswith("'"):  # Hex literal
            return operand[2:-1] #直接把單引號裡的 hex 字串取出來，作為機器碼。
        return None # 不是 C也不是 X，就回 None（代表這一行不輸出任何 object code）。
    
    # RSUB 是「Return from Subroutine」，它的機器格式固定是 4C0000：
    if opcode == '4C':  # RSUB opcode
        return '4C0000' 
        
    if operand == '***':
        return None # operand 空白（佔位 ***），代表這行不該產生 object code，直接跳過。
    
    # 處理不同定址方式
    # operand 裡有逗號，格式通常是 LABEL,X。
    if ',' in operand:  # 索引定址
        base_addr = operand.split(',')[0] # 取逗號前面真正的符號名稱，例如 "BUFFER,X" → "BUFFER"。
        if base_addr in symbol_table: # 若從 symbol_table 拿到那個符號的十六進位地址（hex 字串）
             #symbol_table[base_addr] 拿到的是一個字串，例如 "0039"，表示符號在中間檔裡算出的十六進位位址。
            addr = int(symbol_table[base_addr], 16) # 轉成十進位整數     
            # 0x8000 的二進位是 1000 0000 0000 0000₂ # Set X bit (bit 15) to 1 ＝加上 0x8000，把 index 位元（最高位）打開。
            return f"{opcode}{addr + 0x8000:04X}"  # 再把 opcode（兩位 hex）和這個 16 位位址拼成 6 位 hex 串回傳。
            # 先把 symbol_table裡記錄的十六進位地址轉成整數，加上 0x8000 來開啟 X-bit（索引定址旗標），然後用 f-string 格式化成 4 位大寫 hex，再拼在兩位 Opcode 之後，得到最終的 6 位十六進位機器碼。


    elif operand in symbol_table:  # 直接定址
        addr = int(symbol_table[operand], 16) # 如果 operand 是一個已定義的符號，就取它位址
        return f"{opcode}{addr:04X}" # 直接拼成 opcode + address。
    elif is_valid_decimal(operand):  # 立即值(Immediate value)
        return f"{opcode}{int(operand):04X}" # 如果 operand 看起來是純十進位數字（is_valid_decimal 回 True），就把它當作一個立即數，加在 opcode 後面，轉成 4 位 hex。
    #沒有在symbol table 就報錯
    return None #上面所有情況都不符，就回 None，代表這行不生成 object code（或是格式錯誤留給 Pass 2 後續處理）。

def generate_object_program(symbol_table, intermediate):
    """產生目的碼"""
    global program_start_address, program_length, program_end_address  # 使用全域變數
    
    object_records = []
    current_text = []
    current_start_addr = None

    # 找到程式名稱（START 那行的 label）
    program_name = "PROG"  # 預設名稱
    for record in intermediate:
        if record[3] == "START":
            program_name = record[2] if record[2] != "***" else "PROG"
            break

    # 產生 H record（使用 pass one 計算好的值）
    h_record = f"H {program_name:6s} {program_start_address:06X} {program_length:06X}"
    object_records.append(h_record)

    # Find the entry point from END instruction's operand
    end_record = next((record for record in intermediate if record[3] == "END"), None) #找第一筆 mnemonic == "END" 的記錄，存到 end_record。
    entry_point = program_start_address  # 預設執行入口
    if end_record and end_record[4] != '***': #找到了 END 且 operand（欄位 [4]）不是佔位 ***：
        if end_record[4] in symbol_table:
            entry_point = int(symbol_table[end_record[4]], 16) #若這 operand在 symbol_table 裡有定義，就把它的地址拿來當 entry_point。
        else:
            print(f"Warning: END 指令的運算元 {end_record[4]} 未定義，使用程式起始位址") #若沒定義，就印警告。保留預設的 program_start_address。
    
    for record in intermediate: #逐行取出中間檔的每筆記錄，各欄位依序拆給對應變數。
        line_num, loc_hex, label, mnemonic, operand, opcode_hex, addressing = record
        
        # H/T/E 只放 Text Record，所以碰到 START/END 這種偽指令直接略過。
        if mnemonic in ["START", "END"]:
            continue
            
        # Skip RESW and RESB (reserved space)RESW/RESB 也不產生機械碼，但它們中途會中斷 Text Record 流程：
        if mnemonic in ["RESW", "RESB"]:
            if current_text:  # 如果已經在 current_text 累積程式碼，就先把它 flush（寫出一筆 T-record），
                text_length = len(''.join(current_text)) // 2
                # Format text record with spaces between object codes
                text_content = ' '.join(current_text)
                text_record = f"T {current_start_addr:06X} {text_length:02X} {text_content}"
                object_records.append(text_record)
                
                # 再把 current_text 清空、current_start_addr 重設，下行繼續處理下一條。
                current_text = [] 
                current_start_addr = None
            continue
        
        # Generate object code for instruction
        # 呼叫前面那個 generate_object_code 函式，把助記符、operand、opcode_hex、addressing 全丟進去，取回 6 位元機器碼字串。
        obj_code = generate_object_code(operand, opcode_hex, symbol_table, addressing)
        if obj_code is None:
            continue #回傳 None，表示這行不產生機器碼（或格式錯），就跳下一行。
        

        # 如果 current_text 剛好是空（上一筆 T-record 已經 flush 或才剛開始），就把這行的位址當成這筆 Text Record 的起始地址 current_start_addr。
        if current_start_addr is None:
            current_start_addr = int(loc_hex, 16)
        
        # Check if adding this code would exceed maximum text record length (30 bytes)
        # Note: Now we need to consider actual object code length, not string length
        # 每 2 個 hex 字元 才等於 1 個位元組，所以要 len(hex_str)//2 才能拿到「實際佔用的位元組數」，才能正確控制一條 T-record 最多 30 bytes。
        current_length = sum(len(code.replace(" ", "")) // 2 for code in current_text) #已累積的機碼共多少 bytes。
        new_code_length = len(obj_code.replace(" ", "")) // 2 #這行機碼幾 bytes。
        
        if current_length + new_code_length > 30: # 如果加起來會超過 30，必須先 flush目前的那筆 T-record：
            # Output current text record and start new one
            text_length = current_length
            text_content = ' '.join(current_text)
            text_record = f"T {current_start_addr:06X} {text_length:02X} {text_content}"
            object_records.append(text_record) # 把這筆 T-record 加到 object_records。
            current_text = [] #重設 current_text，把這行的位址當下一筆的新起始位址。
            current_start_addr = int(loc_hex, 16)
        
        current_text.append(obj_code)
    
    # Output final text record if any
    if current_text:
        text_length = sum(len(code.replace(" ", "")) // 2 for code in current_text)
        text_content = ' '.join(current_text)
        text_record = f"T {current_start_addr:06X} {text_length:02X} {text_content}"
        object_records.append(text_record) # 把這筆 T-record 加到 object_records。
    
    # Generate End record with entry point
    end_record = f"E {entry_point:06X}" # 最後一行 E entry，entry point 用之前算好的 entry_point，補成 6 位 hex。
    object_records.append(end_record)
    
    return object_records # 把完整的 object_records list 回傳給呼叫端。

# 印出中間檔
def print_intermediate(intermediate):
    """Print intermediate code in a formatted table"""
    print("\n==== Intermediate Code ====")
    print("Line  Loc    Label   Mnemonic  Operand    OpCode  Addressing")
	#Line：行號,Loc：(位址hex),Label,Mnemonic(助記符),Operand,OpCode：對應的機器碼 (hex) 或佔位,Addressing：定址方式 (direct 或 indexed)    
    
    print("-" * 60)
    for record in intermediate:
        line_num, loc_hex, label, mnemonic, operand, opcode_hex, addressing = record
        # Format each field with proper width
        print(f"{line_num:4s}  {loc_hex:6s} {label:8s} {mnemonic:8s} {operand:10s} {opcode_hex:6s} {addressing}") #定址方式不設寬度，直接印出。
    print("-" * 60)

def passTwo(symbol_table, intermediate, operandConfirm): 
    # symbol_table：Pass 1 存好的標籤→位址對照。
	# intermediate：Pass 1 的中間檔，每行已解析好的欄位。
	# operandConfirm：Pass 1 蒐集的、之後要檢查是否在符號表裡的操作數清單。
    """
    passTwo 做「找不到 symbol」的檢查，
    如果所有 operandConfirm 中的 base_operand 不在 symbol_table，就報錯。
    成功後產生目的碼。
    """
    errors2 = []
    
    print("\n==== Symbol Table ====")
    print("Label   Address")
    print("-" * 20)
    for label, addr in symbol_table.items():
        print(f"{label:8s} {addr}")
    print("-" * 20)

    print("\n==== Operand Confirmation ====")
    print("Line  Symbol")
    print("-" * 20)
    for ln, sym in operandConfirm:
        print(f"{ln:4d}  {sym}")
    print("-" * 20)

    print_intermediate(intermediate)
    

    for ln, sym in operandConfirm: #針對每個待確認的 base_operand
        # split the sym to get the label if it is indexed addressing
        if ',' in sym: # 索引定址：操作數裡有逗號，格式通常是 LABEL,X。
            sym = sym.split(',')[0] # 取逗號前面真正的符號名稱，例如 "BUFFER,X" → "BUFFER"。
        if sym not in symbol_table: # 如果這個符號不在 symbol_table 裡，就報錯。
            errors2.append(f"[passTwo] 錯誤：第 {ln} 行使用了未定義的符號 {sym}。")

    if errors2:
        print("\n==== passTwo 發現的錯誤 ====")
        for e in errors2:
            print(e)
        sys.exit(1)

    # 產生目的碼
    print("\n==== 產生目的碼 ====")
    object_program = generate_object_program(symbol_table, intermediate)
    
    # 寫入目的碼檔案
    with open('passTwo_output.txt', 'w') as f:
        for record in object_program:
            print(record)
            f.write(record + '\n')

    print("\n目的碼已寫入 passTwo_output.txt")

# ===================================================================================
#                                      Main
# ===================================================================================
if __name__ == "__main__":
    if len(sys.argv) < 2: #使用者沒有提供「要組譯的檔案名稱」。
        print("Usage: python3 SIC_twoPass.py <source_file>")
        sys.exit(1)

    source_file = sys.argv[1] #把使用者在命令列輸入的第一個參數（通常是原始程式檔名）存到 source_file。

    # 先建立 opcode_table(要確保和 opCode.txt 在同一資料夾
    opcode_table = {}
    try:
        with open("opCode.txt", 'r') as f:
            for line in f:
                line = line.strip() # 去掉前後空白
                if not line: # 如果這行是空行，就跳過。
                    continue
                parts = line.split() # 用空白分隔，parts[0] 是助記符，parts[1] 是對應的 hex 字串。
                if len(parts) >= 2:
                    mnem = parts[0].upper() # 助記符轉大寫
                    code = parts[1].upper() # 機器碼轉大寫
                    opcode_table[mnem] = code  # 把這對助記符和機器碼存到 opcode_table 裡。
    except FileNotFoundError:
        print("找不到 opCode.txt，請放在相同目錄下")
        sys.exit(1)

    # passOne
    # 呼叫 passOne，把「源碼程式檔名」和「opcode_table」丟進去
    symbol_table, intermediate, operandConfirm, pass1_errors = passOne(source_file, opcode_table)
    #得到：
    # 1. symbol_table：標籤→位址對照表
    # 2. intermediate：中間檔記錄（已解析出的各欄位陣列）
    # 3. operandConfirm：需要在 Pass 2 再確認的操作數清單
    # 4. pass1_errors：Pass 1 檢查過程中蒐集到的錯誤訊息    

    # 不論 passOne 有無錯，都先把 pass1_errors 列出來
    if pass1_errors:
        print("==== passOne 發現的錯誤 ====")
        for e in pass1_errors:
            print(e)

    # 再執行 passTwo，一次檢查所有未定義符號
    passTwo(symbol_table, intermediate, operandConfirm)
    # 負責︰
    # 1. 印出符號表(symbol_table)、中間檔(intermediate)、操作數清單(operandConfirm)
    # 2. 檢查 operandConfirm 裡面所有符號是否都在 symbol_table
    # 3. 若有未定義就印錯誤並 sys.exit(1)；否則才正式產出目標程式（H/T/E）。


    # 若到這裡都沒 exit，表示 passTwo 也沒找到「使用未定義符號」
    # （後續才可以做真正的物件碼組合 H/T/E，如果需要就自行加上去）