"""IGMP-FLOW 起動エントリーポイント (app.py)

このスクリプトは、PyInstallerでスタンドアロン実行ファイルをビルドした際に、
`backend` パッケージの依存関係が ModuleNotFoundError になる現象を防ぐための
プロジェクトルート直下の統合起動エントリーポイントです。
引数定義は `backend.main` と共用します(二重管理を避けるため)。
"""

import os
import sys

# カレントディレクトリをサーチパスの最優先に追加してパッケージ参照を確実にする
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# コマンドプロンプト非表示（--noconsole）時に stdout/stderr が None になりクラッシュするのを防ぐセーフガード
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w', encoding='utf-8')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w', encoding='utf-8')

# 英語/仏語版Windows等(cp1252)では日本語ログを表せず UnicodeEncodeError で落ちるため(Issue #1)、
# 表せない文字は置換して出力を続ける
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors='replace')
    except (AttributeError, ValueError):  # reconfigure非対応のストリームはそのまま使う
        pass

from backend.main import main

if __name__ == "__main__":
    main()
