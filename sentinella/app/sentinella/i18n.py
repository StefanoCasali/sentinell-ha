"""Testi in due lingue (italiano e inglese).

Ogni testo è scritto nel punto in cui serve, in entrambe le lingue:
`t("testo", "text")` restituisce subito quello nella lingua corrente, `L(...)`
lo conserva per le tabelle definite a livello di modulo e si risolve con `s()`.
"""

import os

SUPPORTED = ("it", "en")
_lang = "en"


def set_language(code: str | None) -> str:
    """Imposta la lingua: l'italiano per i codici 'it*', l'inglese per tutto il resto."""
    global _lang
    _lang = "it" if str(code or "").lower().startswith("it") else "en"
    return _lang


def language() -> str:
    return _lang


def t(it: str, en: str) -> str:
    return it if _lang == "it" else en


class L:
    """Testo bilingue risolto al momento dell'uso (per costanti di modulo)."""

    __slots__ = ("it", "en")

    def __init__(self, it: str, en: str):
        self.it, self.en = it, en

    def __str__(self) -> str:
        return self.it if _lang == "it" else self.en

    def format(self, **values) -> str:
        return str(self).format(**values)


def s(value):
    """Risolve un L (o una lista di L); lascia invariato tutto il resto."""
    if isinstance(value, L):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [s(v) for v in value]
    return value


def resolve(option: str | None, ha_language: str | None) -> str:
    """Lingua da usare: quella scelta nelle opzioni, altrimenti quella di Home Assistant."""
    choice = str(option or "auto").lower()
    if choice in SUPPORTED:
        return set_language(choice)
    return set_language(ha_language or os.environ.get("SENTINELLA_LANG") or "en")
