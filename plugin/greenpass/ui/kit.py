"""Settings components with translated texts, dialogs, and page refresh."""

import time

from ui.settings import Divider, EditText as _EditText, Header as _Header, Selector as _Selector, \
    Switch as _Switch, Text as _Text

from ..android import on_ui
from ..i18n import t

SETTINGS_ACTIVITY = "com.exteragram.messenger.plugins.ui.PluginSettingsActivity"


def _tr(kwargs):
    for key in ("text", "subtext", "hint"):
        if kwargs.get(key):
            kwargs[key] = t(kwargs[key])
    if "items" in kwargs:
        kwargs["items"] = [t(i) if isinstance(i, str) else i for i in kwargs["items"]]
    return kwargs


def Header(text):
    return _Header(text=t(text))


def Text(text, subtext=None, icon=None, on_click=None, page=None, accent=False, red=False):
    kwargs = _tr({"text": text, "subtext": subtext})
    if icon:
        kwargs["icon"] = icon
    if on_click is not None:
        kwargs["on_click"] = lambda *_: on_click()
    if page is not None:
        kwargs["create_sub_fragment"] = page
    if accent:
        kwargs["accent"] = True
    if red:
        kwargs["red"] = True
    return _Text(**{k: v for k, v in kwargs.items() if v is not None})


def Switch(key, text, default, on_change=None, subtext=None, icon=None):
    kwargs = _tr({"key": key, "text": text, "default": bool(default), "subtext": subtext})
    if icon:
        kwargs["icon"] = icon
    if on_change is not None:
        kwargs["on_change"] = on_change
    return _Switch(**{k: v for k, v in kwargs.items() if v is not None})


def Selector(key, text, items, default, on_change=None, icon=None):
    kwargs = _tr({"key": key, "text": text, "items": list(items), "default": int(default)})
    if icon:
        kwargs["icon"] = icon
    if on_change is not None:
        kwargs["on_change"] = on_change
    return _Selector(**kwargs)


def EditText(key, hint, default="", on_change=None, multiline=False):
    kwargs = _tr({"key": key, "hint": hint, "default": str(default or "")})
    if multiline:
        kwargs["multiline"] = True
    if on_change is not None:
        kwargs["on_change"] = on_change
    return _EditText(**kwargs)


__all__ = ["Divider", "Header", "Text", "Switch", "Selector", "EditText", "activity", "confirm", "choose",
           "ask_text", "refresh_pages"]


def activity():
    try:
        from client_utils import get_last_fragment
        fragment = get_last_fragment()
        if fragment is not None and fragment.getParentActivity() is not None:
            return fragment.getParentActivity()
    except Exception:
        pass
    try:
        from hook_utils import find_class
        return find_class("org.telegram.messenger.AndroidUtilities").getActivity()
    except Exception:
        return None


def _builder():
    from ui.alert import AlertDialogBuilder
    current = activity()
    return AlertDialogBuilder(current) if current is not None else None


def confirm(title, message, yes_text, on_yes, no_text="Отмена", danger=False):
    """Two-button dialog; on_yes runs on the UI thread."""
    def show():
        builder = _builder()
        if builder is None:
            return
        builder.set_title(t(title))
        builder.set_message(t(message))

        def yes(dialog, _which):
            dialog.dismiss()
            on_yes()

        builder.set_positive_button(t(yes_text), yes)
        builder.set_negative_button(t(no_text), lambda dialog, _which: dialog.dismiss())
        dialog = builder.show()
        if danger:
            try:
                from org.telegram.ui.ActionBar import Theme
                dialog.getButton(-1).setTextColor(Theme.getColor(Theme.key_text_RedBold))
            except Exception:
                pass
    on_ui(show)


def choose(title, items, on_pick):
    """List dialog; on_pick(index) runs on the UI thread."""
    def show():
        builder = _builder()
        if builder is None:
            return
        builder.set_title(t(title))

        def picked(dialog, which):
            dialog.dismiss()
            on_pick(int(which))

        builder.set_items([t(i) for i in items], picked)
        builder.set_negative_button(t("Отмена"), lambda dialog, _which: dialog.dismiss())
        builder.show()
    on_ui(show)


def ask_text(title, hint, on_done, initial=""):
    """Dialog with one text field; on_done(text) runs on the UI thread."""
    def show():
        current = activity()
        builder = _builder()
        if builder is None:
            return
        from android.widget import EditText as AndroidEditText, FrameLayout
        from org.telegram.messenger import AndroidUtilities
        from org.telegram.ui.ActionBar import Theme
        field = AndroidEditText(current)
        field.setHint(t(hint))
        field.setText(str(initial or ""))
        field.setSingleLine(True)
        try:
            field.setTextColor(Theme.getColor(Theme.key_dialogTextBlack))
            field.setHintTextColor(Theme.getColor(Theme.key_dialogTextHint))
        except Exception:
            pass
        box = FrameLayout(current)
        padding = AndroidUtilities.dp(24)
        box.setPadding(padding, AndroidUtilities.dp(8), padding, 0)
        box.addView(field)
        builder.set_title(t(title))
        builder.set_view(box)

        def done(dialog, _which):
            dialog.dismiss()
            on_done(str(field.getText() or "").strip())

        builder.set_positive_button(t("Готово"), done)
        builder.set_negative_button(t("Отмена"), lambda dialog, _which: dialog.dismiss())
        builder.show()
    on_ui(show)


_last_refresh = [0.0, False]


def refresh_pages(plugin_id):
    """Rebuild every open settings page of the plugin (debounced to ~4 per second)."""
    if _last_refresh[1]:
        return
    _last_refresh[1] = True
    delay = max(0, int((0.25 - (time.monotonic() - _last_refresh[0])) * 1000))

    def run():
        _last_refresh[1] = False
        _last_refresh[0] = time.monotonic()
        try:
            from org.telegram.messenger import NotificationCenter
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.pluginSettingsRegistered, plugin_id)
            return
        except Exception:
            pass
        try:
            from hook_utils import find_class
            find_class("com.exteragram.messenger.plugins.PluginsController").getInstance().loadPluginSettings(plugin_id)
        except Exception:
            pass

    on_ui(run, delay or 50)
