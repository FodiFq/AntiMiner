# AntiMiner

AntiMiner — утилита для обнаружения скрытых майнеров на Windows. Показывает подозрительные процессы и ведет логи.  
Это моя первая программа, созданная для поиска и выявления скрытых майнеров на Windows. Она помогает обнаружить процессы, загружающие процессор, и позволяет очистить временные файлы. Программа полностью Open-Source, с поддержкой API-ключей для проверки процессов на наличие вирусов.

---

## 📌 Почему AntiMiner лучше, чем Диспетчер задач?

Скрытые майнеры могут обнаруживать запуск Диспетчера задач и автоматически завершаться, чтобы их нельзя было увидеть.  
AntiMiner работает иначе:  
- Он не вызывается стандартными системными процессами, поэтому не привлекает внимание вредоносных программ.  
- Написан на Python, который установлен почти на каждом ПК, что делает его работу незаметной.  
- Программа не требует установки и может запускаться прямо из файла.  

---

## 🔍 Как работает программа?

1. Запускает скрытый мониторинг процессов.  
2. Проверяет загрузку процессора каждым процессом.  
3. Записывает в лог все подозрительные процессы, загружающие CPU выше заданного порога.  
4. Отображает список возможных угроз в удобном интерфейсе.  
5. Позволяет очистить временные файлы, где могут скрываться вредоносные файлы.  

---

## 📥 Установка

1. Убедитесь, что у вас установлен Python 3.x. Если нет, скачайте его с [официального сайта](https://www.python.org/downloads/).  
2. Установите необходимые зависимости, выполнив команду в терминале:  
   ```bash
   pip install requests psutil
3. Скачайте AntiMiner.exe (или исходный код с GitHub).
4. Запустите программу.
5. ажмите "Начать мониторинг", чтобы проверить ПК.

## 🔑 Настройка API-ключей

Для проверки процессов на вирусы программа использует API VirusTotal и Abuse.ch. Чтобы настроить API-ключи:

1. Получите API-ключи:

        VirusTotal

        Abuse.ch

2. Скопируйте файл config.example.json и переименуйте его в config.json.

3. Впишите свои API-ключи в файл config.json:
    {
  "api_url": "ВАШ_API_ОТ_ABUSE.CH",
  "vt_key": "ВАШ_API_ОТ_VIRUSTOTAL"
    }
4. Запустите программу.

## 🚀 Возможности

✅ Отслеживание процессов и их загрузки CPU
Программа мониторит все процессы и выявляет те, которые загружают процессор выше заданного порога.

✅ Ведение лога подозрительных процессов
Все подозрительные процессы записываются в лог для дальнейшего анализа.

✅ Очистка временных файлов
Программа позволяет очистить временные файлы, где могут скрываться вредоносные программы.

✅ Простой и удобный интерфейс
Программа имеет интуитивно понятный интерфейс, который подходит даже для начинающих пользователей.

## 📜 Пример работы

После запуска программы и нажатия кнопки "Начать мониторинг", AntiMiner начнет отслеживать процессы. Если какой-то процесс загружает CPU выше заданного порога, он будет записан в лог и отмечен как подозрительный.
Пример лога:
[2023-10-01 12:34:56] - suspicious_process.exe (PID: 1234) -> 85%  
Путь: C:\Windows\Temp\suspicious_process.exe  
Время работы: 120 секунд  

## 🛠️ Зависимости

Программа использует следующие библиотеки Python:

    requests — для работы с API.

    psutil — для мониторинга процессов.

    tkinter — для графического интерфейса.
 
## 🚧 Планы на будущее

    Добавление поддержки Linux.

    Улучшение интерфейса.

    Добавление автоматического обновления программы.

    Интеграция с другими антивирусными API.

## ❓ Поддержка

Если у вас есть вопросы или предложения, в телеграмме @FodiFq или напишите мне на почту: fqfodi@gmail.com.

## 🙏 Благодарности

Спасибо всем, кто поддерживает этот проект! Если вам нравится AntiMiner, поставьте звезду на GitHub ⭐️.