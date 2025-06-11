# SIC Two-Pass Assembler

這是一個用 Python 實現的 SIC (Simplified Instructional Computer) 組譯器，採用兩遍處理方式將 SIC 組合語言程式轉換為目的碼。

## 功能特點
- 完整支援 SIC 指令集
- Two-Pass Assembler
- 支援索引定址 (Indexed Addressing)
- 完整的錯誤檢查和報告
- 支援程式內註解
- 支援多種資料型態 (WORD, BYTE, RESW, RESB)

## 系統需求

- Python 3.7.2 或更高版本
- 執行主程式指令：python3 SIC_twoPass.py SIC_test.txt


passTwo_output.txt 是輸出檔
passOne_output.txt 是中間檔
## 檔案結構

- `SIC_twoPass.py`: 主程式檔案
- `opCode.txt`: SIC 指令集的操作碼表
- `SIC_test.txt`: 測試用的組合語言程式
- `passOne_output.txt`: Pass One 的輸出檔案（中間檔）
- `passTwo_output.txt`: Pass Two 的輸出檔案（目的碼）

## 使用方法

1. 確保你的系統已安裝 Python 3.7.2 或更高版本
2. 在命令列中執行以下指令：

```bash
python3 SIC_twoPass.py <輸入檔案名稱>

```

例如：
```bash
python3 SIC_twoPass.py SIC_test.txt
```

### 特殊指令
- `START`: 程式起始位址
- `END`: 程式結束
- `WORD`: 配置一個字組
- `BYTE`: 配置位元組資料
- `RESW`: 保留字組空間
- `RESB`: 保留位元組空間

### 資料型態
1. WORD 指令：
   - 接受十進位整數
   - 例：`THREE WORD 3`

2. BYTE 指令：
   - 支援字元格式：`C'字串'`
   - 支援十六進位格式：`X'十六進位數'`
   - 例：`EOF BYTE C'EOF'` 或 `INPUT BYTE X'F1'`

3. RESW/RESB 指令：
   - 接受十進位整數，表示要保留的空間大小
   - 例：`BUFFER RESB 4096`

### 註解支援
- 行註解：以 `.` 開頭
- 行內註解：在指令後加上 `.` 和註解內容

## 錯誤處理

組譯器會檢查並報告以下錯誤：
- 重複的標籤定義
- 未定義的符號
- 非法的運算元格式
- 非法的指令格式
- 超出範圍的位址
- 程式長度超出限制

## 輸出檔案

1. Pass One 輸出 (`passOne_output.txt`):
   - 包含位址計算和符號表建立的中間結果
   - 顯示每行的位置計數器值和基本解析結果

2. Pass Two 輸出 (`passTwo_output.txt`):
   - 包含最終的目的碼
   - 採用 SIC 標準目的碼格式

## 範例程式

```assembly
COPY START 1000
FIRST STL RETADR
CLOOP JSUB RDREC
      LDA LENGTH
      COMP ZERO
      JEQ ENDFIL
      JSUB WRREC
      J CLOOP
ENDFIL LDA EOF
      STA BUFFER
      LDA THREE
      STA LENGTH
      JSUB WRREC
      LDL RETADR
      RSUB
EOF   BYTE C'EOF'
THREE WORD 3
ZERO  WORD 0
RETADR RESW 1
LENGTH RESW 1
BUFFER RESB 4096
END FIRST
```

## 注意事項

1. 確保輸入檔案使用正確的格式和語法
2. 程式長度不能超過 SIC 的記憶體限制
3. 標籤必須是唯一的
4. 所有使用的符號必須有定義 