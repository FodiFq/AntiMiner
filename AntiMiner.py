import os
import psutil
import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel
import threading
import time
import json
import requests
import datetime
import hashlib
import shutil

# Константы для файлов
l = "Лог.txt"  # Основной лог
s = "Лог с подозрительными процессами.txt"  # Лог для подозрительных процессов
v = "Подозрительные процессы.txt"  # Лог для вредоносных процессов
c = "config.json"  # Конфигурационный файл

# Функция для инициализации файлов (создание, если они не существуют)
def il():
    for f in [l, s, v]:
        try:
            with open(f, "a", encoding="utf-8") as x:
                pass
        except:
            pass

def clear_cache():
    temp_dirs = [
        os.path.expandvars(r"%TEMP%"),
        os.path.expandvars(r"C:\\Windows\\Temp"),
        os.path.expandvars(r"%USERPROFILE%\\AppData\\Local\\Temp"),
        os.path.expandvars(r"%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files"),
        os.path.expandvars(r"%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache"),
    ]
    
    for temp_dir in temp_dirs:
        if os.path.exists(temp_dir):
            try:
                for filename in os.listdir(temp_dir):
                    file_path = os.path.join(temp_dir, filename)
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path, ignore_errors=True)
                messagebox.showinfo("Очистка", f"Очищено: {temp_dir}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка очистки {temp_dir}: {e}")


# Функция для загрузки конфигурации из файла
def lc():
    if os.path.exists(c):  # Если файл конфигурации существует
        with open(c, "r", encoding="utf-8") as x:
            return json.load(x)  # Загружаем и возвращаем данные
    return {"c": 65, "api_url": "", "vt_key": ""}  # Возвращаем конфигурацию по умолчанию

# Загружаем конфигурацию
config = lc()

# Получаем URL API и ключ VirusTotal из конфигурации
u = config.get("api_url", "")  # URL для API
vt_k = config.get("vt_key", "")  # Ключ для VirusTotal

# Функция для записи логов в файл
def wl(f, t):
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Текущее время
        with open(f, "a", encoding="utf-8") as x:
            x.write(f"[{timestamp}] {t}\n")  # Записываем лог с временной меткой
    except:
        pass

# Функция для проверки файла через VirusTotal
def chk_vt(h):
    if not vt_k:  # Если ключ VirusTotal не указан, пропускаем проверку
        return False
    url = f"https://www.virustotal.com/api/v3/files/{h}"  # URL для запроса
    hds = {"x-apikey": vt_k}  # Заголовки с API-ключом
    try:
        r = requests.get(url, headers=hds)  # Отправляем GET-запрос
        if r.status_code == 200:  # Если запрос успешен
            d = r.json()  # Парсим JSON-ответ
            s = d["data"]["attributes"].get("last_analysis_stats", {})  # Получаем статистику
            if s.get("malicious", 0) > 0:  # Если файл помечен как вредоносный
                return True
    except:
        pass
    return False

# Функция для проверки файла через API
def ch_api(fp):
    if not u:  # Если URL API не указан, пропускаем проверку
        return False
    try:
        with open(fp, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()  # Вычисляем хэш файла
        d = {"query": "get_info", "hash": h}  # Данные для POST-запроса
        r = requests.post(u, data=d)  # Отправляем POST-запрос
        if r.status_code == 200:  # Если запрос успешен
            j = r.json()  # Парсим JSON-ответ
            if "data" in j and len(j["data"]) > 0:  # Если данные содержат информацию о вредоносности
                return True
        if chk_vt(h):  # Проверяем через VirusTotal, если API не дал результата
            return True
    except:
        pass
    return False

# Основная функция мониторинга процессов
def mn():
    global a
    d, r, ch = {}, {}, {}  # Словари для хранения данных о процессах
    while a:  # Пока мониторинг активен
        try:
            pids = set()  # Множество для хранения PID текущих процессов
            for pr in psutil.process_iter(['pid', 'name', 'cpu_percent', 'exe', 'create_time']):  # Итерация по процессам
                try:
                    i, n, u, p, t = pr.info['pid'], pr.info['name'], pr.info['cpu_percent'], pr.info['exe'], pr.info['create_time']
                    pids.add(i)  # Добавляем PID в множество
                    if p is None:  # Если путь к исполняемому файлу отсутствует, пропускаем
                        continue
                    if i not in r:  # Если процесс новый, записываем время его запуска
                        r[i] = time.time() - t
                    if u > th.get() and d.get(i, 0) < 5:  # Если загрузка CPU превышает порог
                        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        log_entry = f"{timestamp} - {n} (PID: {i}) -> {u}%\nПуть: {p}\nВремя работы: {int(r[i])} секунд\n"
                        tx.insert(tk.END, log_entry + "\n")  # Добавляем запись в текстовое поле
                        tx.yview(tk.END)  # Прокручиваем текстовое поле вниз
                        wl(l, log_entry)  # Записываем лог в файл

                        if ch_api(p):  # Если процесс вредоносный
                            wl(v, f"⚠️ ВРЕДОНОСНЫЙ ПРОЦЕСС ОБНАРУЖЕН:\n{log_entry}")  # Записываем в лог вредоносных процессов
                    d[i] = u  # Обновляем загрузку CPU для процесса
                    ch[i] = (n, p, i)  # Сохраняем информацию о процессе
                except:
                    pass
            for i in list(ch.keys()):  # Проверяем завершенные процессы
                if i not in pids:
                    n, p, pid = ch.pop(i)  # Удаляем процесс из словаря
                    wl(s, f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {n} (PID: {pid}) -> Закрылся. Путь: {p}")  # Записываем лог
        except:
            pass
        time.sleep(3)  # Пауза между итерациями

# Функция для запуска мониторинга
def sm():
    global a
    a = True  # Активируем мониторинг
    lb.config(text="Мониторинг", fg="green")  # Обновляем статус
    threading.Thread(target=mn, daemon=True).start()  # Запускаем мониторинг в отдельном потоке
    messagebox.showinfo("Старт", "Мониторинг начат!")  # Показываем сообщение

# Функция для остановки мониторинга
def tm():
    global a
    a = False  # Останавливаем мониторинг
    lb.config(text="Остановлен", fg="red")  # Обновляем статус
    messagebox.showinfo("Стоп", "Мониторинг остановлен!")  # Показываем сообщение

# Функция для открытия основного лога
def ol():
    try:
        os.startfile(l)  # Открываем файл лога
    except:
        pass

# Функция для открытия лога подозрительных процессов
def osl():
    try:
        os.startfile(s)  # Открываем файл лога
    except:
        pass

# Функция для открытия лога вредоносных процессов
def ov():
    try:
        os.startfile(v)  # Открываем файл лога
    except:
        pass

# Функция для открытия окна с FAQ
def fq():
    w = Toplevel(rt)  # Создаем новое окно
    w.title("FAQ")  # Устанавливаем заголовок
    w.geometry("400x300")  # Устанавливаем размер окна
    w.resizable(False, False)  # Запрещаем изменение размера
    t = """Привет, это мое первое приложение. Оно поможет найти возможные майнеры.\n\n1. Очистка кеша — удаляет временные файлы.\n2. Начать мониторинг — запускает отслеживание процессов.\n3. Остановить мониторинг — завершает отслеживание.\n4. Порог загрузки CPU — Вы можете сами выбрать порог с которым будут отображаться приложения."""
    tk.Label(w, text=t, wraplength=380, justify="left", padx=10, pady=10).pack()  # Добавляем текст в окно

# Инициализация переменной для управления мониторингом
a = False
il()  # Инициализация файлов

# Создание графического интерфейса
rt = tk.Tk()
rt.title("AntiMiner")  # Заголовок окна
rt.geometry("600x780")  # Размер окна
rt.resizable(False, False)  # Запрет на изменение размера

# Метка для отображения статуса мониторинга
lb = tk.Label(rt, text="Остановлен", fg="red")
lb.pack(pady=5)

# Метка и поле для ввода порога загрузки CPU
tk.Label(rt, text="Выберите действие").pack(pady=20)
th = tk.IntVar(value=config["c"])  # Устанавливаем значение по умолчанию из конфигурации
tk.Label(rt, text="Порог загрузки CPU (%):").pack()
tk.Entry(rt, textvariable=th).pack(pady=5)

# Кнопки управления
tk.Button(rt, text="Начать мониторинг", command=sm).pack(pady=10)
tk.Button(rt, text="Остановить мониторинг", command=tm).pack(pady=10)
tk.Button(rt, text="Открыть лог", command=ol).pack(pady=10)
tk.Button(rt, text="Лог подозрительных процессов", command=osl).pack(pady=10)
tk.Button(rt, text="Лог вредоносных процессов", command=ov).pack(pady=10)
tk.Button(rt, text="FAQ", command=fq).pack(pady=10)
tk.Button(rt, text="Очистить кэш и временные файлы", command=clear_cache).pack(pady=10)

# Текстовое поле для отображения логов
tx = scrolledtext.ScrolledText(rt, width=50, height=15)
tx.pack(pady=10)

# Кнопка для выхода из программы
tk.Button(rt, text="Выход", command=rt.quit).pack(pady=10)

# Запуск основного цикла обработки событий
rt.mainloop()