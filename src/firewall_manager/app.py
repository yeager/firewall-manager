"""Firewall Manager — GTK4/Adwaita frontend for UFW."""
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, GLib, Gio, Pango
import subprocess, threading, re, gettext
from datetime import datetime

APP_ID = "io.github.yeager.FirewallManager"
_ = gettext.gettext

def run_ufw(*args, use_pkexec=True):
    """Run ufw command, optionally via pkexec."""
    cmd = ["pkexec", "ufw"] + list(args) if use_pkexec else ["ufw"] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() + "\n" + result.stderr.strip()
    except Exception as e:
        return f"Error: {e}"

def get_ufw_status():
    """Get current UFW status and rules."""
    try:
        result = subprocess.run(["sudo", "ufw", "status", "verbose"],
                                capture_output=True, text=True, timeout=10)
        output = result.stdout.strip()
        if not output:
            # Try with pkexec
            result = subprocess.run(["pkexec", "ufw", "status", "verbose"],
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()
        return output
    except Exception as e:
        return f"Error: {e}"

def parse_ufw_status(output):
    """Parse ufw status verbose output into structured data."""
    info = {"active": False, "default_incoming": "deny", "default_outgoing": "allow",
            "logging": "off", "rules": [], "raw": output}

    if "Status: active" in output:
        info["active"] = True

    m = re.search(r"Default:\s*(\w+)\s*\(incoming\),\s*(\w+)\s*\(outgoing\)", output)
    if m:
        info["default_incoming"] = m.group(1)
        info["default_outgoing"] = m.group(2)

    m = re.search(r"Logging:\s*(\w+)", output)
    if m:
        info["logging"] = m.group(1)

    # Parse rules
    in_rules = False
    for line in output.split("\n"):
        if line.startswith("--"):
            in_rules = True
            continue
        if in_rules and line.strip():
            # Parse rule line: "22/tcp    ALLOW IN    Anywhere"
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 3:
                info["rules"].append({
                    "to": parts[0],
                    "action": parts[1],
                    "from": parts[2] if len(parts) > 2 else "Anywhere",
                    "raw": line.strip()
                })
    return info


class RuleRow(Gtk.ListBoxRow):
    def __init__(self, rule, index):
        super().__init__()
        self.rule = rule
        self.rule_index = index

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_start(12); box.set_margin_end(12)
        box.set_margin_top(6); box.set_margin_bottom(6)

        # Action icon
        action = rule["action"].upper()
        if "ALLOW" in action:
            icon = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
            icon.add_css_class("success")
        elif "DENY" in action:
            icon = Gtk.Image.new_from_icon_name("action-unavailable-symbolic")
            icon.add_css_class("error")
        elif "REJECT" in action:
            icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
            icon.add_css_class("warning")
        else:
            icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
        box.append(icon)

        # Rule details
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        vbox.set_hexpand(True)
        title = Gtk.Label(label=f"{rule['to']}  ←  {rule['from']}", xalign=0)
        title.add_css_class("heading")
        vbox.append(title)
        sub = Gtk.Label(label=rule["action"], xalign=0)
        sub.add_css_class("dim-label")
        vbox.append(sub)
        box.append(vbox)

        # Delete button
        del_btn = Gtk.Button(icon_name="edit-delete-symbolic", tooltip_text=_("Delete rule"))
        del_btn.add_css_class("flat")
        del_btn.add_css_class("error")
        box.append(del_btn)
        self.delete_btn = del_btn

        self.set_child(box)


class AddRuleDialog(Adw.Dialog):
    def __init__(self):
        super().__init__(title=_("Add Firewall Rule"))
        self.result = None

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        cancel_btn = Gtk.Button(label=_("Cancel"))
        cancel_btn.connect("clicked", lambda b: self.close())
        header.pack_start(cancel_btn)
        add_btn = Gtk.Button(label=_("Add Rule"))
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._on_add)
        header.pack_end(add_btn)
        toolbar.add_top_bar(header)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_start(24); content.set_margin_end(24)
        content.set_margin_top(12); content.set_margin_bottom(24)
        content.set_size_request(400, -1)

        # Action
        action_group = Adw.PreferencesGroup(title=_("Action"))
        self.action_row = Adw.ComboRow(title=_("Action"))
        self.action_model = Gtk.StringList.new(["allow", "deny", "reject", "limit"])
        self.action_row.set_model(self.action_model)
        action_group.add(self.action_row)
        content.append(action_group)

        # Direction
        dir_group = Adw.PreferencesGroup(title=_("Direction"))
        self.dir_row = Adw.ComboRow(title=_("Direction"))
        self.dir_model = Gtk.StringList.new(["in", "out"])
        self.dir_row.set_model(self.dir_model)
        dir_group.add(self.dir_row)
        content.append(dir_group)

        # Port/Service
        port_group = Adw.PreferencesGroup(title=_("Port / Service"))
        self.port_entry = Adw.EntryRow(title=_("Port or service (e.g. 22, 80/tcp, ssh)"))
        port_group.add(self.port_entry)
        content.append(port_group)

        # From
        from_group = Adw.PreferencesGroup(title=_("Source"))
        self.from_entry = Adw.EntryRow(title=_("From IP/subnet (empty = any)"))
        from_group.add(self.from_entry)
        content.append(from_group)

        # Comment
        comment_group = Adw.PreferencesGroup(title=_("Comment"))
        self.comment_entry = Adw.EntryRow(title=_("Comment (optional)"))
        comment_group.add(self.comment_entry)
        content.append(comment_group)

        toolbar.set_content(content)
        self.set_child(toolbar)
        self.set_content_width(450)
        self.set_content_height(550)

    def _on_add(self, btn):
        action = self.action_model.get_string(self.action_row.get_selected())
        direction = self.dir_model.get_string(self.dir_row.get_selected())
        port = self.port_entry.get_text().strip()
        from_addr = self.from_entry.get_text().strip()
        comment = self.comment_entry.get_text().strip()

        if not port:
            return

        cmd_parts = [action, direction]
        if from_addr:
            cmd_parts.extend(["from", from_addr, "to", "any", "port", port])
        else:
            cmd_parts.append(port)
        if comment:
            cmd_parts.extend(["comment", comment])

        self.result = cmd_parts
        self.close()


class FirewallManagerWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Firewall Manager", default_width=800, default_height=700)
        self.ufw_info = None
        self.dark_mode = False

        header = Adw.HeaderBar()
        # Theme toggle
        theme_btn = Gtk.Button(icon_name="display-brightness-symbolic", tooltip_text=_("Toggle theme"))
        theme_btn.connect("clicked", self._toggle_theme)
        header.pack_end(theme_btn)
        # Menu
        menu = Gio.Menu()
        menu.append(_("About"), "win.about")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        header.pack_end(menu_btn)
        # Refresh
        refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Refresh"))
        refresh_btn.connect("clicked", lambda b: self._refresh())
        header.pack_end(refresh_btn)

        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self._show_about)
        self.add_action(about_action)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_box.append(header)

        # Status banner
        self.status_group = Adw.PreferencesGroup(title=_("Firewall Status"))
        self.status_group.set_margin_start(12); self.status_group.set_margin_end(12)
        self.status_group.set_margin_top(8)

        self.active_row = Adw.SwitchRow(title=_("Firewall Enabled"))
        self.active_row.connect("notify::active", self._on_toggle_firewall)
        self.status_group.add(self.active_row)

        self.incoming_row = Adw.ActionRow(title=_("Default Incoming"), subtitle="deny")
        self.status_group.add(self.incoming_row)
        self.outgoing_row = Adw.ActionRow(title=_("Default Outgoing"), subtitle="allow")
        self.status_group.add(self.outgoing_row)
        self.logging_row = Adw.ActionRow(title=_("Logging"), subtitle="off")
        self.status_group.add(self.logging_row)
        main_box.append(self.status_group)

        # Quick profiles
        profile_group = Adw.PreferencesGroup(title=_("Quick Profiles"))
        profile_group.set_margin_start(12); profile_group.set_margin_end(12)
        profile_group.set_margin_top(8)
        profile_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        profile_box.set_margin_top(4); profile_box.set_margin_bottom(4)
        for label, cmds in [("SSH (22)", ["allow", "22/tcp"]),
                            ("HTTP/S (80,443)", ["allow", "80,443/tcp"]),
                            ("DNS (53)", ["allow", "53"]),
                            (_("Reset All"), ["reset"])]:
            btn = Gtk.Button(label=label)
            if "reset" in cmds:
                btn.add_css_class("destructive-action")
            else:
                btn.add_css_class("pill")
            btn.connect("clicked", self._on_profile, cmds)
            profile_box.append(btn)
        profile_group.add(profile_box)
        main_box.append(profile_group)

        # Rules list
        rules_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        rules_header.set_margin_start(12); rules_header.set_margin_end(12)
        rules_header.set_margin_top(12)
        rules_label = Gtk.Label(label=_("Rules"), xalign=0, hexpand=True)
        rules_label.add_css_class("title-3")
        rules_header.append(rules_label)
        add_btn = Gtk.Button(icon_name="list-add-symbolic", tooltip_text=_("Add rule"))
        add_btn.add_css_class("suggested-action")
        add_btn.connect("clicked", self._on_add_rule)
        rules_header.append(add_btn)
        main_box.append(rules_header)

        sw = Gtk.ScrolledWindow(vexpand=True)
        sw.set_margin_start(12); sw.set_margin_end(12)
        sw.set_margin_top(4); sw.set_margin_bottom(4)
        self.rules_listbox = Gtk.ListBox()
        self.rules_listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        self.rules_listbox.add_css_class("boxed-list")
        self.rules_listbox.set_placeholder(Gtk.Label(label=_("No rules configured")))
        sw.set_child(self.rules_listbox)
        main_box.append(sw)

        # Status bar
        self.statusbar = Gtk.Label(label=_("Ready"), xalign=0)
        self.statusbar.set_margin_start(12); self.statusbar.set_margin_end(12)
        self.statusbar.set_margin_top(4); self.statusbar.set_margin_bottom(4)
        self.statusbar.add_css_class("dim-label")
        main_box.append(self.statusbar)

        self.set_content(main_box)
        self._toggling = False
        self._refresh()

    def _set_status(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.statusbar.set_label(f"[{ts}] {msg}")

    def _toggle_theme(self, btn):
        mgr = Adw.StyleManager.get_default()
        self.dark_mode = not self.dark_mode
        mgr.set_color_scheme(Adw.ColorScheme.FORCE_DARK if self.dark_mode else Adw.ColorScheme.FORCE_LIGHT)

    def _refresh(self):
        self._set_status(_("Refreshing..."))
        def worker():
            output = get_ufw_status()
            info = parse_ufw_status(output)
            GLib.idle_add(self._update_ui, info)
        threading.Thread(target=worker, daemon=True).start()

    def _update_ui(self, info):
        self.ufw_info = info
        self._toggling = True
        self.active_row.set_active(info["active"])
        self._toggling = False
        self.incoming_row.set_subtitle(info["default_incoming"])
        self.outgoing_row.set_subtitle(info["default_outgoing"])
        self.logging_row.set_subtitle(info["logging"])

        # Update rules
        child = self.rules_listbox.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.rules_listbox.remove(child)
            child = nxt

        for i, rule in enumerate(info["rules"]):
            row = RuleRow(rule, i + 1)
            row.delete_btn.connect("clicked", self._on_delete_rule, i + 1)
            self.rules_listbox.append(row)

        self._set_status(f"{'Active' if info['active'] else 'Inactive'} — {len(info['rules'])} rules")

    def _on_toggle_firewall(self, row, param):
        if self._toggling:
            return
        action = "enable" if row.get_active() else "disable"
        self._set_status(f"Running ufw {action}...")
        def worker():
            # For enable/disable, need to pass --force to avoid prompt
            if action == "enable":
                result = run_ufw("--force", "enable")
            else:
                result = run_ufw("disable")
            GLib.idle_add(self._on_cmd_done, result)
        threading.Thread(target=worker, daemon=True).start()

    def _on_profile(self, btn, cmds):
        if "reset" in cmds:
            self._set_status("Resetting UFW...")
            def worker():
                result = run_ufw("--force", "reset")
                GLib.idle_add(self._on_cmd_done, result)
            threading.Thread(target=worker, daemon=True).start()
        else:
            self._set_status(f"Adding rule: ufw {' '.join(cmds)}")
            def worker():
                result = run_ufw(*cmds)
                GLib.idle_add(self._on_cmd_done, result)
            threading.Thread(target=worker, daemon=True).start()

    def _on_add_rule(self, btn):
        dialog = AddRuleDialog()
        dialog.connect("closed", self._on_add_dialog_closed, dialog)
        dialog.present(self)

    def _on_add_dialog_closed(self, dlg, dialog):
        if dialog.result:
            self._set_status(f"Adding rule: ufw {' '.join(dialog.result)}")
            def worker():
                result = run_ufw(*dialog.result)
                GLib.idle_add(self._on_cmd_done, result)
            threading.Thread(target=worker, daemon=True).start()

    def _on_delete_rule(self, btn, index):
        self._set_status(f"Deleting rule {index}...")
        def worker():
            result = run_ufw("--force", "delete", str(index))
            GLib.idle_add(self._on_cmd_done, result)
        threading.Thread(target=worker, daemon=True).start()

    def _on_cmd_done(self, result):
        self._set_status(result.strip()[:100])
        self._refresh()

    def _show_about(self, *args):
        about = Adw.AboutDialog(
            application_name="Firewall Manager",
            application_icon=APP_ID,
            version="0.1.0",
            developer_name="Daniel Nylander",
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/yeager/firewall-manager",
            issue_url="https://github.com/yeager/firewall-manager/issues",
            translator_credits="https://www.transifex.com/danielnylander/firewall-manager/",
            developers=["Daniel Nylander"],
            copyright="© 2026 Daniel Nylander",
            comments=_("GTK4 frontend for UFW firewall"),
        )
        about.present(self)


class FirewallManagerApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_activate(self):
        win = self.get_active_window()
        if not win:
            win = FirewallManagerWindow(self)
        win.present()

    def do_startup(self):
        Adw.Application.do_startup(self)
        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *a: self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Control>q"])


def main():
    app = FirewallManagerApp()
    app.run()

if __name__ == "__main__":
    main()
