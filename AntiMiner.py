import os
import psutil
import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel
import threading
import time
import json
import requests

l = "Лог.txt"
s = "Лог с подозрительными процессами.txt"
c = "config.json"
u = "https://mb-api.abuse.ch/api/v1/"
k = "7b399be330cd8310316138a86e6589d896e4de1038298c13"

def il():
    for f in [l, s]:
        try:
            with open(f, "a", encoding="utf-8") as x:
                pass
        except:
            pass

def lc():
    if os.path.exists(c):
        with open(c, "r", encoding="utf-8") as x:
            return json.load(x)
    return {"c": 65}

def sc(d):
    with open(c, "w", encoding="utf-8") as x:
        json.dump(d, x)

def wl(f, t):
    try:
        with open(f, "a", encoding="utf-8") as x:
            x.write(t + "\n")
    except:
        pass

def mn():
    global a
    d, r, ch = {}, {}, {}
    while a:
        try:
            pids = set()
            for pr in psutil.process_iter(['pid', 'name', 'cpu_percent', 'exe', 'create_time']):
                try:
                    i, n, u, p, t = pr.info['pid'], pr.info['name'], pr.info['cpu_percent'], pr.info['exe'], pr.info['create_time']
                    pids.add(i)
                    if p is None:
                        continue
                    if i not in r:
                        r[i] = time.time() - t
                    if u > th.get() and d.get(i, 0) < 5:
                        log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {n} (PID: {i}) -> {u}%\nПуть: {p}\nВремя работы: {int(r[i])} секунд\n"
                        tx.insert(tk.END, log_entry + "\n")
                        tx.yview(tk.END)
                        wl(l, log_entry)
                    d[i] = u
                    ch[i] = (n, p, i)
                except:
                    pass
            for i in list(ch.keys()):
                if i not in pids:
                    n, p, pid = ch.pop(i)
                    wl(s, f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {n} (PID: {pid}) -> Закрылся. Путь: {p}")
        except:
            pass
        time.sleep(3)

def sm():
    global a
    a = True
    lb.config(text="Мониторинг", fg="green")
    threading.Thread(target=mn, daemon=True).start()
    messagebox.showinfo("Старт", "Мониторинг начат!")

def tm():
    global a
    a = False
    lb.config(text="Остановлен", fg="red")
    messagebox.showinfo("Стоп", "Мониторинг остановлен!")

def ol():
    try:
        os.startfile(l)
    except:
        pass

def osl():
    try:
        os.startfile(s)
    except:
        pass

def fq():
    w = Toplevel(rt)
    w.title("FAQ")
    w.geometry("400x300")
    w.resizable(False, False)
    t = """Привет, это мое первое приложение. Оно поможет найти возможные майнеры.\n\n1. Очистка кеша — удаляет временные файлы.\n2. Начать мониторинг — запускает отслеживание процессов.\n3. Остановить мониторинг — завершает отслеживание.\n4. Порог загрузки CPU — Вы можете сами выбрать порог с которым будут отображаться приложения."""
    tk.Label(w, text=t, wraplength=380, justify="left", padx=10, pady=10).pack()

a = False
il()

rt = tk.Tk()
rt.title("AntiMiner")
rt.geometry("600x700")
rt.resizable(False, False)

lb = tk.Label(rt, text="Остановлен", fg="red")
lb.pack(pady=5)

tk.Label(rt, text="Выберите действие").pack(pady=20)
th = tk.IntVar(value=lc()["c"])
tk.Label(rt, text="Порог загрузки CPU (%):").pack()
tk.Entry(rt, textvariable=th).pack(pady=5)
tk.Button(rt, text="Начать мониторинг", command=sm).pack(pady=10)
tk.Button(rt, text="Остановить мониторинг", command=tm).pack(pady=10)
tk.Button(rt, text="Открыть лог", command=ol).pack(pady=10)
tk.Button(rt, text="Лог подозрительных процессов", command=osl).pack(pady=10)
tk.Button(rt, text="FAQ", command=fq).pack(pady=10)

tx = scrolledtext.ScrolledText(rt, width=50, height=15)
tx.pack(pady=10)

tk.Button(rt, text="Выход", command=rt.quit).pack(pady=10)

rt.mainloop()
