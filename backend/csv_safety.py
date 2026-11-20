"""CSVインジェクション対策 (csv_safety.py)

機器名(mDNS)などはネットワーク上の第三者が自由に決められるため、「=」「+」「-」「@」で始まる値が
ExcelやGoogleスプレッドシートで数式として評価されると、任意の数式/コマンド実行の足掛かりになります
(CSV/Formula Injection, OWASP)。セルの先頭にシングルクォートを付けて文字列として扱わせます。
"""

from typing import Any

# OWASPが挙げる、数式として解釈され得る先頭文字(タブとCRも含む)
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> Any:
    """文字列セルが数式として解釈されないよう無害化します。文字列以外はそのまま返します。

    Args:
        value (Any): CSVへ書く値。

    Returns:
        Any: 無害化後の値。
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value
