# DPI Detector Fork

Форк `dpi-detector` под практическую оценку серверов и VPN-нод.

Эта версия ориентирована не только на поиск DPI-проблем, но и на быстрый ответ на вопрос: подходит ли конкретный сервер как основная VPN-нода, запасная нода или слабый вариант.

## Что умеет

- проверка подмены DNS и доступности DoH
- проверка доступности доменов по HTTP, TLS 1.2 и TLS 1.3
- проверка TCP 16-20KB блокировок на хостингах и CDN
- подбор белых SNI для ASN, если есть признаки блокировки
- проверка Telegram: download, upload и доступность DC
- итоговый рейтинг пригодности сервера под VPN

## Что добавлено в этом форке

- итоговая оценка `VPN-нода 0-100`
- буквенный рейтинг `A-F`
- краткий блок `Плюсы / Риски / Вывод` в финальной сводке
- автонормализация `tcp16.json` при загрузке
- исправление старых опечаток поля `port` в кастомных целях
- защита от дублей `id` в TCP-целях

## Как читать итог

После прогона тестов в финальной панели выводится:

- `VPN-нода 0-100`
- буква `A-F`
- уровень доверия к оценке
- краткий текстовый вывод

Пример интерпретации:

- `A` — отлично подходит под основную VPN-ноду
- `B` — хорошая нода, но стоит мониторить отдельные риски
- `C` — годится как запасная или нишевая
- `D/F` — плохой кандидат, лучше искать другой маршрут или провайдера

## Важное отличие от upstream

Если вы запускаете официальный образ:

```bash
docker run --rm -it --pull=always ghcr.io/runnin4ik/dpi-detector:latest
```

то вы запускаете **upstream-версию**, а не этот форк.

В official-образе **нет**:

- нашего VPN-рейтинга
- правок описания под форк
- улучшенной нормализации кастомного `tcp16.json`

## Запуск этого форка

### Вариант 1. Python

```bash
git clone https://github.com/kislenka/dpi-detector.git
cd dpi-detector
python -m pip install -r requirements.txt
python dpi_detector.py
```

Пример:

```bash
python dpi_detector.py -t 12345 --batch
```

### Вариант 2. Docker локально из форка

Пока для форка не опубликован отдельный Docker image, самый прямой путь такой:

```bash
git clone https://github.com/kislenka/dpi-detector.git
cd dpi-detector
docker build -t kislenka/dpi-detector .
docker run --rm -it kislenka/dpi-detector
```

С кастомными файлами:

```bash
docker run --rm -it \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/tcp16.json:/app/tcp16.json \
  -v $(pwd)/config.yml:/app/config.yml \
  -v $(pwd)/whitelist_sni.txt:/app/whitelist_sni.txt \
  kislenka/dpi-detector -t 12345
```

### PowerShell

```powershell
docker run --rm -it `
  -v ${PWD}/domains.txt:/app/domains.txt `
  -v ${PWD}/tcp16.json:/app/tcp16.json `
  -v ${PWD}/config.yml:/app/config.yml `
  -v ${PWD}/whitelist_sni.txt:/app/whitelist_sni.txt `
  kislenka/dpi-detector -t 12345
```

## CLI параметры

- `-t`, `--tests` — какие тесты запускать, например `123`, `12345`
- `-p`, `--proxy` — прокси URL
- `-d`, `--domain` — проверить отдельные домены
- `-c`, `--concurrency` — число параллельных запросов
- `-o`, `--output` — сохранить лог в файл
- `--batch` — без вопросов и пауз

## Кастомизация

Можно переопределять:

- `domains.txt` — список доменов
- `tcp16.json` — хосты для TCP 16-20KB теста
- `config.yml` — таймауты, DNS, потоки и другие параметры
- `whitelist_sni.txt` — список белых SNI

Этот форк особенно удобен, если вы держите собственный набор целей под:

- VPN-ноды
- VPS в разных ASN
- CDN и хостинги, которые вы реально используете
- регулярную проверку серверов перед вводом в прод

## Рекомендация по использованию

Для оценки сервера под VPN лучше запускать минимум:

```bash
python dpi_detector.py -t 12345 --batch
```

Именно такой набор обычно дает наиболее полезную итоговую оценку.

## Откуда взят проект

База форка: [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector)

Оригинальному проекту — уважение за сильную основу по DPI-диагностике.

## Лицензия

[MIT](LICENSE)
