# 一、先把目标拆清楚（很重要），这些都是后期功能。
# 1.云同步
# 2.浏览器插件
# 3.自动填充
# 4.跨设备同步
#
# 二、第一版（强烈推荐）功能定义
# 核心功能（V1）
# 1.主密码解锁
# 1.1程序启动 → 输入一个“主密码”
# 1.2主密码正确才能进入主界面
# 2.账号密码管理
# 2.1新增账号（网站 / App 名）
# 2.2用户名
# 2.3密码
# 2.4备注（可选）
# 3.本地加密存储
# 3.1数据保存在本地文件（如 vault.dat）
# 3.2文件内容是 加密的
# 3.3即使别人拿到文件，也看不到明文
# 4.列表查看 / 编辑 / 删除
# 4.1显示账号列表
# 4.2点进去查看密码（可加“显示/隐藏”）
#
# 三、技术选型（全部你现在就能用）
# 1.界面
# 1.1Kivy
# 1.2Windows 上直接跑
# 1.3后期可打包 Android
# 2.数据存储
# 2.1第一阶段：JSON + AES 加密
# 2.2不用数据库，先简单、可控
# 3.加密方案（关键）
# 3.1使用：cryptography 库
# 3.2AES（Fernet 封装，安全且好用）
# 逻辑是：
# 1.AES 本地加密（Fernet + PBKDF2）
# 2.加密密钥
# 3.加密 JSON 数据
# 4.写入 vault.dat

# password_manager_final_confirm_delete.py
import json, os, shutil, base64
from kivy.app import App
from kivy.lang import Builder
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.core.text import LabelBase
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ================== 中文字体 ==================
LabelBase.register(name="MSYH", fn_regular="C:/Windows/Fonts/msyh.ttc")
KV = """
<Label>:
    font_name: "MSYH"
<Button>:
    font_name: "MSYH"
<TextInput>:
    font_name: "MSYH"
"""
Builder.load_string(KV)

# ================== 文件路径 ==================
VAULT_FILE = "vault.dat"
SALT_FILE = "vault_salt.dat"

# ================== 工具函数 ==================
def generate_salt():
    return os.urandom(16)

def save_salt(salt):
    with open(SALT_FILE,"wb") as f:
        f.write(salt)

def load_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE,"rb") as f:
            return f.read()
    else:
        salt = generate_salt()
        save_salt(salt)
        return salt

def generate_fernet(master_password):
    salt = load_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)

def encrypt_data(data, fernet):
    return fernet.encrypt(json.dumps(data).encode())

def decrypt_data(enc_bytes, fernet):
    return json.loads(fernet.decrypt(enc_bytes).decode())

# ================== 弹窗 ==================
def show_message(title, message):
    content = BoxLayout(orientation='vertical', padding=10, spacing=10)
    title_label = Label(text=title, font_name="MSYH", font_size=20, size_hint=(1,0.2))
    content.add_widget(title_label)
    msg_label = Label(text=message, font_name="MSYH", halign="center", valign="middle")
    msg_label.bind(size=msg_label.setter('text_size'))
    content.add_widget(msg_label)
    btn = Button(text="确定", size_hint=(1,0.3), font_name="MSYH")
    content.add_widget(btn)
    popup = Popup(title="", content=content, size_hint=(0.6,0.4))
    btn.bind(on_press=popup.dismiss)
    popup.open()

def ask_input(title, hint_text, callback, password=False):
    content = BoxLayout(orientation='vertical', padding=10, spacing=10)
    title_label = Label(text=title, font_name="MSYH", font_size=20, size_hint=(1,0.2))
    content.add_widget(title_label)
    ti = TextInput(hint_text=hint_text, multiline=False, font_name="MSYH", password=password)
    content.add_widget(ti)
    btn = Button(text="确定", size_hint=(1,0.3), font_name="MSYH")
    content.add_widget(btn)
    popup = Popup(title="", content=content, size_hint=(0.6,0.4))
    def on_ok(instance):
        val = ti.text.strip()
        if val:
            callback(val)
        popup.dismiss()
    btn.bind(on_press=on_ok)
    popup.open()

def ask_file_path(title, callback, save=False):
    from kivy.uix.filechooser import FileChooserListView
    content = BoxLayout(orientation='vertical', spacing=10)
    title_label = Label(text=title, font_name="MSYH", font_size=20, size_hint=(1,0.1))
    content.add_widget(title_label)
    chooser = FileChooserListView(path=os.getcwd())
    content.add_widget(chooser)
    btn = Button(text="确定", size_hint=(1,0.1), font_name="MSYH")
    content.add_widget(btn)
    popup = Popup(title="", content=content, size_hint=(0.8,0.8))
    def on_ok(instance):
        if save:
            path = chooser.path
        else:
            selection = chooser.selection
            if not selection:
                show_message("错误", "未选择文件")
                return
            path = selection[0]
        callback(path)
        popup.dismiss()
    btn.bind(on_press=on_ok)
    popup.open()

# ================== 主应用 ==================
class PasswordManager(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.master_password = None
        self.fernet = None
        self.vault = {"accounts":[],"security":{}}

    # ---------- 主密码页 ----------
    def build_master_page(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=20)
        label = Label(text="请输入主密码", font_size=24, font_name="MSYH")
        layout.add_widget(label)
        ti = TextInput(password=True, multiline=False, font_name="MSYH")
        layout.add_widget(ti)
        btn_login = Button(text="登录", size_hint=(1,0.3), font_name="MSYH")
        layout.add_widget(btn_login)
        btn_recover = Button(text="找回主密码", size_hint=(1,0.3), font_name="MSYH")
        layout.add_widget(btn_recover)

        def login(instance):
            pwd = ti.text.strip()
            if not pwd:
                show_message("错误","请输入主密码")
                return
            self.fernet = generate_fernet(pwd)
            if os.path.exists(VAULT_FILE):
                try:
                    with open(VAULT_FILE,"rb") as f:
                        self.vault = decrypt_data(f.read(), self.fernet)
                    self.master_password = pwd
                    self.root.clear_widgets()
                    self.build_main_page()
                except Exception:
                    show_message("错误","主密码错误或Vault损坏")
            else:
                self.master_password = pwd
                def set_security_answer(ans):
                    self.vault["security"]["answer"] = ans
                    self.save_vault()
                    show_message("提示","Vault已创建")
                    self.root.clear_widgets()
                    self.build_main_page()
                ask_input("设置安全问题答案","请输入安全问题答案", set_security_answer)

        def recover(instance):
            def verify_answer(ans):
                try:
                    if ans == self.vault["security"].get("answer",""):
                        ask_input("重置主密码","请输入新主密码", self.reset_master_password, password=True)
                    else:
                        show_message("错误","安全问题答案错误")
                except Exception:
                    show_message("错误","Vault不存在或损坏")
            ask_input("安全问题验证","请输入安全问题答案", verify_answer)

        btn_login.bind(on_press=login)
        btn_recover.bind(on_press=recover)
        return layout

    def reset_master_password(self, new_pwd):
        self.master_password = new_pwd
        self.fernet = generate_fernet(new_pwd)
        self.save_vault()
        show_message("提示","主密码已重置")

    # ---------- 主界面 ----------
    def build_main_page(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=10)
        btn_layout = BoxLayout(size_hint=(1,0.1))
        btn_add = Button(text="新增账号", font_name="MSYH")
        btn_backup = Button(text="备份 Vault", font_name="MSYH")
        btn_restore = Button(text="恢复 Vault", font_name="MSYH")
        btn_layout.add_widget(btn_add)
        btn_layout.add_widget(btn_backup)
        btn_layout.add_widget(btn_restore)
        layout.add_widget(btn_layout)

        # 滚动列表
        scroll = ScrollView(size_hint=(1,0.9))
        self.list_layout = BoxLayout(orientation='vertical', spacing=5, size_hint_y=None)
        self.list_layout.bind(minimum_height=self.list_layout.setter('height'))
        scroll.add_widget(self.list_layout)
        layout.add_widget(scroll)

        self.refresh_account_list()
        btn_add.bind(on_press=lambda x: self.add_account_popup())
        btn_backup.bind(on_press=lambda x: self.backup_vault())
        btn_restore.bind(on_press=lambda x: self.restore_vault())
        self.root.add_widget(layout)

    # ---------- 账号列表 ----------
    def refresh_account_list(self):
        self.list_layout.clear_widgets()
        for acc in reversed(self.vault.get("accounts", [])):
            acc_box = BoxLayout(size_hint=(1,None), height=40)
            label = Label(text=f"{acc['site']} | {acc['username']}", font_name="MSYH",
                          halign="left", valign="middle")
            label.bind(size=label.setter('text_size'))
            acc_box.add_widget(label)

            # 按钮
            btn_box = BoxLayout(size_hint=(0.4,1))
            btn_view = Button(text="查看", size_hint=(0.33,1), font_name="MSYH")
            btn_edit = Button(text="修改", size_hint=(0.34,1), font_name="MSYH")
            btn_del  = Button(text="删除", size_hint=(0.33,1), font_name="MSYH")
            btn_box.add_widget(btn_view)
            btn_box.add_widget(btn_edit)
            btn_box.add_widget(btn_del)
            acc_box.add_widget(btn_box)
            self.list_layout.add_widget(acc_box)

            # ---------- 查看密码 ----------
            def view_pwd(instance, account=acc):
                scroll_popup = ScrollView(size_hint=(1,1))
                content = BoxLayout(orientation='vertical', spacing=10, size_hint_y=None)
                content.bind(minimum_height=content.setter('height'))

                title_label = Label(text=account['site'], font_name="MSYH", font_size=20,
                                    size_hint_y=None, height=40)
                content.add_widget(title_label)

                pwd_label = Label(text="密码: ******", font_name="MSYH",
                                  halign="left", valign="top", size_hint_y=None, height=30)
                pwd_label.bind(size=pwd_label.setter('text_size'))
                content.add_widget(pwd_label)

                note_text = account.get("note","")
                if note_text:
                    note_label = Label(
                        text=f"备注: {note_text}",
                        font_name="MSYH",
                        halign="left",
                        valign="top",
                        size_hint_y=None
                    )
                    note_label.text_size = (400, None)
                    note_label.bind(texture_size=note_label.setter('size'))
                    content.add_widget(note_label)

                toggle_btn = Button(text="显示密码", size_hint=(1,None), height=40, font_name="MSYH")
                btn_close = Button(text="关闭", size_hint=(1,None), height=40, font_name="MSYH")
                content.add_widget(toggle_btn)
                content.add_widget(btn_close)

                scroll_popup.add_widget(content)
                popup = Popup(title="", content=scroll_popup, size_hint=(0.6,0.6))

                def toggle_pwd(instance):
                    if toggle_btn.text == "显示密码":
                        pwd_label.text = f"密码: {account['password']}"
                        toggle_btn.text = "隐藏密码"
                    else:
                        pwd_label.text = "密码: ******"
                        toggle_btn.text = "显示密码"

                toggle_btn.bind(on_press=toggle_pwd)
                btn_close.bind(on_press=popup.dismiss)
                popup.open()

            btn_view.bind(on_press=view_pwd)

            # ---------- 修改账号 ----------
            def edit_account(instance, account=acc):
                content = BoxLayout(orientation='vertical', spacing=10)
                title_label = Label(text="修改账号", font_name="MSYH", font_size=20, size_hint=(1,0.2))
                content.add_widget(title_label)

                site_input = TextInput(text=account['site'], multiline=False, font_name="MSYH")
                user_input = TextInput(text=account['username'], multiline=False, font_name="MSYH")
                pwd_input  = TextInput(text=account['password'], multiline=False, font_name="MSYH")
                note_input = TextInput(text=account.get('note',''), multiline=True, font_name="MSYH", size_hint_y=None, height=100)

                content.add_widget(site_input)
                content.add_widget(user_input)
                content.add_widget(pwd_input)
                content.add_widget(note_input)

                btn_ok = Button(text="保存修改", size_hint=(1,0.3), font_name="MSYH")
                content.add_widget(btn_ok)
                popup = Popup(title="", content=content, size_hint=(0.6,0.7))

                def save_changes(instance):
                    account['site'] = site_input.text.strip()
                    account['username'] = user_input.text.strip()
                    account['password'] = pwd_input.text.strip()
                    account['note'] = note_input.text.strip()
                    self.save_vault()
                    self.refresh_account_list()
                    popup.dismiss()

                btn_ok.bind(on_press=save_changes)
                popup.open()

            btn_edit.bind(on_press=edit_account)

            # ---------- 删除账号（带确认） ----------
            def del_acc(instance, account=acc):
                content = BoxLayout(orientation='vertical', spacing=10, padding=10)
                label = Label(text=f"确认删除账号：{account['site']} ?", font_name="MSYH", halign="center", valign="middle")
                label.bind(size=label.setter('text_size'))
                content.add_widget(label)
                btn_layout = BoxLayout(size_hint=(1,0.3), spacing=10)
                btn_confirm = Button(text="确定", font_name="MSYH")
                btn_cancel  = Button(text="取消", font_name="MSYH")
                btn_layout.add_widget(btn_confirm)
                btn_layout.add_widget(btn_cancel)
                content.add_widget(btn_layout)
                popup = Popup(title="", content=content, size_hint=(0.5,0.3))

                def confirm_delete(instance):
                    self.vault["accounts"].remove(account)
                    self.save_vault()
                    self.refresh_account_list()
                    popup.dismiss()

                btn_confirm.bind(on_press=confirm_delete)
                btn_cancel.bind(on_press=popup.dismiss)
                popup.open()

            btn_del.bind(on_press=del_acc)

    # ---------- 新增账号 ----------
    def add_account_popup(self):
        content = BoxLayout(orientation='vertical', spacing=10)
        title_label = Label(text="新增账号", font_name="MSYH", font_size=20, size_hint=(1,0.2))
        content.add_widget(title_label)
        site_input = TextInput(hint_text="网站/应用名", multiline=False, font_name="MSYH")
        user_input = TextInput(hint_text="用户名", multiline=False, font_name="MSYH")
        pwd_input = TextInput(hint_text="密码", multiline=False, font_name="MSYH")
        note_input = TextInput(hint_text="备注", multiline=True, font_name="MSYH", size_hint_y=None, height=100)
        content.add_widget(site_input)
        content.add_widget(user_input)
        content.add_widget(pwd_input)
        content.add_widget(note_input)
        btn_add = Button(text="添加", size_hint=(1,0.3), font_name="MSYH")
        content.add_widget(btn_add)
        popup = Popup(title="", content=content, size_hint=(0.6,0.7))
        def on_add(instance):
            site = site_input.text.strip()
            user = user_input.text.strip()
            pwd = pwd_input.text.strip()
            note = note_input.text.strip()
            if site and user and pwd:
                self.vault["accounts"].append({
                    "site": site,
                    "username": user,
                    "password": pwd,
                    "note": note
                })
                self.save_vault()
                self.refresh_account_list()
                popup.dismiss()
            else:
                show_message("错误","请填写完整信息")
        btn_add.bind(on_press=on_add)
        popup.open()

    # ---------- 备份/恢复 ----------
    def backup_vault(self):
        def do_backup(path):
            try:
                if not os.path.isdir(path):
                    show_message("错误", "请选择一个文件夹作为备份目录")
                    return
                shutil.copy(VAULT_FILE, os.path.join(path, "vault.dat"))
                if os.path.exists(SALT_FILE):
                    shutil.copy(SALT_FILE, os.path.join(path, "vault_salt.dat"))
                show_message("提示","备份成功！两个文件已保存到备份目录")
            except Exception as e:
                show_message("错误", f"备份失败: {e}")
        ask_file_path("选择备份目录", do_backup, save=True)

    def restore_vault(self):
        def do_restore(path):
            try:
                if os.path.isfile(os.path.join(path, "vault.dat")):
                    shutil.copy(os.path.join(path, "vault.dat"), VAULT_FILE)
                if os.path.isfile(os.path.join(path, "vault_salt.dat")):
                    shutil.copy(os.path.join(path, "vault_salt.dat"), SALT_FILE)
                show_message("提示","恢复成功，请重新登录")
                self.root.clear_widgets()
                self.master_password = None
                self.build_master_page()
            except Exception as e:
                show_message("错误", f"恢复失败: {e}")
        ask_file_path("选择恢复目录", do_restore, save=True)

    # ---------- 保存 vault ----------
    def save_vault(self):
        enc = encrypt_data(self.vault, self.fernet)
        with open(VAULT_FILE,"wb") as f:
            f.write(enc)

    def build(self):
        root = BoxLayout()
        self.root = root
        self.root.add_widget(self.build_master_page())
        return root

# ================== 运行 ==================
if __name__ == "__main__":
    PasswordManager().run()
