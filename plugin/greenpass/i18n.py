"""UI strings are written in Russian; t() translates them for English and Chinese."""

from .i18n_data import EN, ZH

_cached_lang = None


def _lang_from(value):
    text = str(value or "").strip().lower()
    if text.startswith(("ru", "рус")):
        return "ru"
    if text.startswith(("zh", "chi")) or "chinese" in text:
        return "zh"
    return ""


def detect_language():
    try:
        from org.telegram.messenger import LocaleController
        info = LocaleController.getInstance().getCurrentLocaleInfo()
        if info is not None:
            for attr in ("shortName", "pluralLangCode"):
                lang = _lang_from(getattr(info, attr, None))
                if lang:
                    return lang
    except Exception:
        pass
    try:
        from java.util import Locale
        lang = _lang_from(Locale.getDefault().getLanguage())
        if lang:
            return lang
    except Exception:
        pass
    return "en"


def reset_language():
    global _cached_lang
    _cached_lang = None


def language():
    global _cached_lang
    if _cached_lang is None:
        _cached_lang = detect_language()
    return _cached_lang


def t(text, *args):
    """Translate a Russian UI string; extra args are %-formatted after translation."""
    text = str(text or "")
    lang = language()
    if lang != "ru":
        catalog = ZH if lang == "zh" else EN
        text = catalog.get(text) or (EN.get(text) if lang == "zh" else None) or text
    if args:
        try:
            text = text % args
        except (TypeError, ValueError):
            pass
    return text
