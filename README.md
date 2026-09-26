# rakutenai.cpp

evex-dev/rakutenai をC++に移植したやつ。

## 元repo
evex-devのやつ: https://github.com/evex-dev/rakutenai (thx)

- 本家の機能をまるごと移植
- ヘッダー1個インクルードするだけで使える
- C++11からC++26まで全部動く
- 変なライブラリ不要（Windows標準のWinHTTP/BCryptだけで動く）
- 暗号化もハードウェアアクセラレーション使って詰めてる
- -Wall -Wextra -Werror で警告ゼロ
