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
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

from backend.main import main

if __name__ == "__main__":
    main()
