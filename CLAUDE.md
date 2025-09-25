# SPHINCS+ 時間測量實現指南

## 🎯 目標
測量 SPHINCS+-SHAKE-256s-simple 簽名過程中不同階段的執行時間，提供詳細的性能分析報告。

## 📊 實現結果 (已完成)
時間測量功能已成功實現並測試通過，典型測試結果：

```
SPHINCS+-SHAKE-256s-simple Signing Timing Results:
  Preprocessing:   0.013 ms (12.776 us)      - 0.0%
  FORS Signing:    96.182 ms (96182.121 us)  - 33.5%
  Merkle Signing:  190.811 ms (190811.221 us) - 66.5%
  Total Signing:   287.006 ms (287006.408 us)
```

## 🔧 要測量的階段

### 1. 消息預處理階段 (Message Preprocessing)
- **功能**: 生成隨機值 (optrand)、計算消息隨機化值 R、消息雜湊
- **代碼位置**: `randombytes()` → `gen_message_random()` → `hash_message()`
- **性能特徵**: 最快的階段，通常 < 0.1ms，佔總時間 0.0%
- **測量點**:
  ```c
  timing_start(&timing.preprocessing);
  randombytes(optrand, SPX_N);
  gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);
  hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
  timing_end(&timing.preprocessing);
  ```

### 2. FORS 簽名階段 (FORS Signing)
- **功能**: 使用 FORS (Forest of Random Subsets) 對消息雜湊進行簽名
- **代碼位置**: `fors_sign()` 調用
- **性能特徵**: 中等耗時，通常 ~96ms，佔總時間 33.5%
- **測量點**:
  ```c
  timing_start(&timing.fors_signing);
  fors_sign(sig, root, mhash, &ctx, wots_addr);
  timing_end(&timing.fors_signing);
  ```

### 3. 多層 Merkle 樹簽名階段 (Multi-layer Merkle Tree Signing)
- **功能**: 對每一層 (SPX_D 層) 進行 WOTS+ 簽名生成和 Merkle 認證路徑計算
- **代碼位置**: `for (i = 0; i < SPX_D; i++)` 整個循環
- **性能特徵**: 最耗時的階段，通常 ~191ms，佔總時間 66.5%
- **測量點**:
  ```c
  timing_start(&timing.merkle_signing);
  for (i = 0; i < SPX_D; i++) {
      // WOTS+ 簽名和 Merkle 認證路徑計算
      merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
      // ...
  }
  timing_end(&timing.merkle_signing);
  ```

## ⚠️ 關鍵發現與陷阱

### 🔴 **雙版本問題 (最重要的發現)**
SPHINCS+ 有兩個實現版本，系統會根據 CPU 自動選擇：
- `pqclean_sphincs-shake-256s-simple_clean/` - 通用版本
- `pqclean_sphincs-shake-256s-simple_avx2/` - AVX2 優化版本

**陷阱**: 如果只修改 clean 版本，在支援 AVX2 的系統上看不到時間測量輸出！

**解決方案**: **必須同時修改兩個版本的 sign.c 文件**

### 🔴 **PQClean 命名空間重映射**
函數名會被自動重新映射：
- `crypto_sign_signature` → `PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature`
- 定義位置: `params.h:4` → `#define SPX_NAMESPACE(s) PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_##s`

這就是為什麼修改 `crypto_sign_signature` 函數有效的原因。

## 📁 實現的文件結構

### 已創建/修改的文件
```
src/sig/sphincs/pqclean_sphincs-shake-256s-simple_clean/
├── timing.h                    # 時間測量頭文件 (新創建)
└── sign.c                      # 修改添加時間測量代碼

src/sig/sphincs/pqclean_sphincs-shake-256s-simple_avx2/
├── timing.h                    # 時間測量頭文件 (複製自 clean 版本)
└── sign.c                      # 修改添加時間測量代碼
```

### timing.h 內容概要
```c
typedef struct {
    struct timespec start;
    struct timespec end;
    double elapsed_ns;
} timing_ctx;

typedef struct {
    timing_ctx preprocessing;
    timing_ctx fors_signing;
    timing_ctx merkle_signing;
    timing_ctx total;
} sphincs_timing_ctx;

// 提供納秒級精度的時間測量函數
static inline void timing_start(timing_ctx *ctx);
static inline void timing_end(timing_ctx *ctx);
static inline void print_timing_results(sphincs_timing_ctx *timing);
```

## 🚀 完整實現步驟

### 1. 環境準備
```bash
cd /home/wayne/project/github/liboqs
mkdir build && cd build
```

### 2. 創建時間測量頭文件
將 `timing.h` 複製到兩個目錄：
```bash
cp timing.h src/sig/sphincs/pqclean_sphincs-shake-256s-simple_clean/
cp timing.h src/sig/sphincs/pqclean_sphincs-shake-256s-simple_avx2/
```

### 3. 修改兩個 sign.c 文件
在兩個版本的 `sign.c` 文件中：

**a) 添加頭文件包含:**
```c
#include "timing.h"
```

**b) 在 `crypto_sign_signature` 函數中添加:**
```c
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk) {
    spx_ctx ctx;
    sphincs_timing_ctx timing;  // ← 新增

    // ... 原有代碼 ...

    timing_start(&timing.total);  // ← 開始總計時

    // 階段 1: 消息預處理
    timing_start(&timing.preprocessing);
    randombytes(optrand, SPX_N);
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    timing_end(&timing.preprocessing);

    // 階段 2: FORS 簽名
    timing_start(&timing.fors_signing);
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    timing_end(&timing.fors_signing);

    // 階段 3: Merkle 樹簽名
    timing_start(&timing.merkle_signing);
    for (i = 0; i < SPX_D; i++) {
        // ... Merkle 簽名循環 ...
    }
    timing_end(&timing.merkle_signing);

    timing_end(&timing.total);
    print_timing_results(&timing);  // ← 輸出結果

    // ... 原有代碼 ...
}
```

### 4. 編譯系統
```bash
cmake -GNinja ..
ninja
```

### 5. 創建測試程序
```c
// sphincs_timing_test.c
#include <oqs/oqs.h>

int main(void) {
    OQS_init();
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256s_simple);

    // 創建密鑰、消息、簽名緩衝區
    // 調用 OQS_SIG_sign() 會觸發時間測量輸出

    OQS_SIG_free(sig);
    OQS_destroy();
    return 0;
}
```

### 6. 編譯並執行測試
```bash
gcc -I../build/include sphincs_timing_test.c -L../build/lib -loqs -lssl -lcrypto -o test
./test
```

## 🧪 驗證成功的標誌

如果實現正確，應該看到類似輸出：
```
SPHINCS+-SHAKE-256s-simple Signing Timing Results:
  Preprocessing:   0.012776 ms (12.776 us)
  FORS Signing:    96.182121 ms (96182.121 us)
  Merkle Signing:  190.811221 ms (190811.221 us)
  Total Signing:   287.006408 ms (287006.408 us)
  Percentage breakdown:
    Preprocessing:   0.0%
    FORS Signing:    33.5%
    Merkle Signing:  66.5%
```

## 🚨 常見問題排除

### 問題 1: 沒有時間測量輸出
**原因**: 只修改了 clean 版本，系統使用了 AVX2 版本
**解決**: 確保兩個版本都修改了

### 問題 2: 編譯錯誤
**原因**: 缺少 `#include "timing.h"` 或 timing.h 文件不存在
**解決**: 檢查頭文件路徑和包含語句

### 問題 3: 連結錯誤
**原因**: 缺少 OpenSSL 庫連結
**解決**: 編譯時添加 `-lssl -lcrypto`

### 問題 4: 找不到 oqs.h
**原因**: 使用了錯誤的包含路徑
**解決**: 使用 `-I../build/include`

## 📈 性能分析洞察

從測量結果可以得出：
1. **Merkle 樹簽名是瓶頸**: 佔用 66.5% 的時間
2. **FORS 簽名次之**: 佔用 33.5% 的時間
3. **消息預處理可忽略**: 佔用 < 0.1% 的時間

這些數據對於算法優化和性能調優非常有價值。

## 🎯 項目狀態
- ✅ **完成**: 時間測量功能已全面實現並測試通過
- ✅ **驗證**: 在 AVX2 支援的系統上成功輸出時間測量結果
- ✅ **文檔**: 完整記錄實現過程和注意事項
- ✅ **可重現**: 提供完整的重現步驟

**總結**: SPHINCS+ 時間測量功能已成功實現，可以提供精確的性能分析數據。