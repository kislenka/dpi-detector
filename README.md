# DPI Detector

Инструмент для практической оценки серверов и VPN-нод.

Эта версия помогает быстро понять, подходит ли конкретный сервер под основную VPN-ноду, запасную ноду или слабый вариант, и одновременно показывает сетевые аномалии на DNS, TLS, HTTP, TCP 16-20KB и Telegram.

## Возможности

- проверка подмены DNS и доступности DoH
- проверка доменов по HTTP, TLS 1.2 и TLS 1.3
- проверка TCP 16-20KB блокировок на хостингах и CDN
- подбор белых SNI для ASN при наличии блокировок
- проверка Telegram: download, upload и доступность DC
- итоговая оценка пригодности сервера под VPN

## Что добавлено

- рейтинг `VPN-нода 0-100`
- буквенная оценка `A-F`
- блок `Плюсы / Риски / Вывод` в финальной сводке
- автонормализация `tcp16.json`
- исправление ошибочного поля `port` в кастомных целях
- защита от дублей `id` в TCP-целях
- автопубликация Docker-образа в GHCR через GitHub Actions

## Как читать итог

После прогона тестов в финальной панели выводится:

- `VPN-нода 0-100`
- буква `A-F`
- уровень доверия к оценке
- краткий текстовый вывод

Пример:

- `A` — отлично подходит под основную VPN-ноду
- `B` — хорошая нода, но стоит мониторить отдельные риски
- `C` — нормальна как запасная или нишевая
- `D/F` — плохой кандидат, лучше искать другой маршрут или провайдера

## Запуск

### Python

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

### Docker через GHCR

```bash
docker run --rm -it ghcr.io/kislenka/dpi-detector:latest
```

С кастомными файлами:

```bash
docker run --rm -it \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/tcp16.json:/app/tcp16.json \
  -v $(pwd)/config.yml:/app/config.yml \
  -v $(pwd)/whitelist_sni.txt:/app/whitelist_sni.txt \
  ghcr.io/kislenka/dpi-detector:latest -t 12345
```

### Docker локально

```bash
git clone https://github.com/kislenka/dpi-detector.git
cd dpi-detector
docker build -t kislenka/dpi-detector .
docker run --rm -it kislenka/dpi-detector
```

### PowerShell

```powershell
docker run --rm -it `
  -v ${PWD}/domains.txt:/app/domains.txt `
  -v ${PWD}/tcp16.json:/app/tcp16.json `
  -v ${PWD}/config.yml:/app/config.yml `
  -v ${PWD}/whitelist_sni.txt:/app/whitelist_sni.txt `
  ghcr.io/kislenka/dpi-detector:latest -t 12345
```

## CLI параметры

- `-t`, `--tests` — какие тесты запускать, например `123`, `12345`
- `-p`, `--proxy` — прокси URL
- `-d`, `--domain` — проверить отдельные домены
- `-c`, `--concurrency` — число параллельных запросов
- `-o`, `--output` — сохранить лог в файл
- `--batch` — запуск без вопросов и пауз

## Кастомизация

Можно переопределять:

- `domains.txt` — список доменов
- `tcp16.json` — хосты для TCP 16-20KB теста
- `config.yml` — таймауты, DNS, потоки и другие параметры
- `whitelist_sni.txt` — список белых SNI

Эта версия удобна, если у вас есть собственный набор целей под:

- VPN-ноды
- VPS в разных ASN
- CDN и хостинги, которыми вы реально пользуетесь
- регулярную проверку серверов перед вводом в прод

## Рекомендация по использованию

Для полноценной оценки VPN-ноды лучше запускать:

```bash
python dpi_detector.py -t 12345 --batch
```

или:

```bash
docker run --rm -it ghcr.io/kislenka/dpi-detector:latest -t 12345 --batch
```

## Репозиторий

GitHub: [https://github.com/kislenka/dpi-detector](https://github.com/kislenka/dpi-detector)

## Лицензия

[MIT](LICENSE)
