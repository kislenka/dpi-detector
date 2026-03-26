import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from cli.console import console


def wait_and_exit(code: int = 1):
    print("\nНажмите любую клавишу для выхода...")
    try:
        import msvcrt
        msvcrt.getch()
    except ImportError:
        input()
    sys.exit(code)


def get_base_dir() -> Path:
    """Возвращает путь к директории запуска."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def get_resource_path(relative_path: str) -> Path:
    """Ищет файл сначала снаружи, затем во внутреннем bundle PyInstaller."""
    base_dir = get_base_dir()
    external_path = base_dir / relative_path

    if external_path.exists():
        return external_path

    if hasattr(sys, "_MEIPASS"):
        bundled_path = Path(sys._MEIPASS) / relative_path
        if bundled_path.exists():
            return bundled_path

    return external_path


def load_domains(filepath: str = "domains.txt") -> List[str]:
    """Загружает список доменов из файла."""
    path = get_resource_path(filepath)

    if not path.exists():
        console.print("[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
        console.print(f"[red]Путь: {path}[/red]")
        console.print(f"[yellow]Положите {filepath} рядом с программой.[/yellow]")
        wait_and_exit()

    try:
        with open(path, "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    except Exception as e:
        console.print(f"[bold red]Ошибка чтения файла {filepath}: {e}[/bold red]")
        wait_and_exit()


def _normalize_tcp_targets(raw_items: Any, filepath: str) -> List[Dict[str, Any]]:
    if not isinstance(raw_items, list):
        console.print(f"[bold red]ОШИБКА: {filepath} должен содержать JSON-массив![/bold red]")
        wait_and_exit()

    normalized: List[Dict[str, Any]] = []
    skipped = 0
    repaired_ports = 0
    duplicate_ids = 0
    seen_ids: Dict[str, int] = {}

    for index, item in enumerate(raw_items, start=1):
        if not isinstance(item, dict):
            skipped += 1
            console.print(f"[yellow]Пропущена TCP-цель #{index}: ожидался JSON-объект.[/yellow]")
            continue

        entry = dict(item)

        # Поддерживаем старую/кастомную опечатку ",port".
        if "port" not in entry and ",port" in entry:
            entry["port"] = entry.pop(",port")
            repaired_ports += 1

        missing = [key for key in ("id", "provider", "ip") if not entry.get(key)]
        if missing:
            skipped += 1
            console.print(
                f"[yellow]Пропущена TCP-цель #{index}: не хватает полей {', '.join(missing)}.[/yellow]"
            )
            continue

        try:
            entry["port"] = int(entry.get("port", 443))
        except (TypeError, ValueError):
            skipped += 1
            console.print(
                f"[yellow]Пропущена TCP-цель {entry.get('id', '#'+str(index))}: некорректный port.[/yellow]"
            )
            continue

        base_id = str(entry["id"]).strip() or f"TARGET-{index}"
        seen_ids[base_id] = seen_ids.get(base_id, 0) + 1
        if seen_ids[base_id] > 1:
            duplicate_ids += 1
            entry["id"] = f"{base_id}-DUP{seen_ids[base_id]}"
        else:
            entry["id"] = base_id

        normalized.append(entry)

    if repaired_ports:
        console.print(
            f"[yellow]Исправлено TCP-целей с опечаткой поля port: {repaired_ports}.[/yellow]"
        )
    if duplicate_ids:
        console.print(
            f"[yellow]Найдены дубли ID в TCP-целях: {duplicate_ids}. "
            f"К повторам добавлен суффикс -DUPN.[/yellow]"
        )
    if skipped:
        console.print(f"[yellow]Пропущено некорректных TCP-целей: {skipped}.[/yellow]")

    return normalized


def load_tcp_targets(filepath: str = "tcp16.json") -> List[Any]:
    """Загружает JSON с целями для TCP-теста."""
    path = get_resource_path(filepath)

    if not path.exists():
        console.print("[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
        console.print(f"[red]Путь: {path}[/red]")
        wait_and_exit()

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_items = json.load(f)
        return _normalize_tcp_targets(raw_items, filepath)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]ОШИБКА: Некорректный JSON в {filepath}![/bold red]")
        console.print(f"[red]{e}[/red]")
        wait_and_exit()
    except Exception as e:
        console.print(f"[bold red]Ошибка чтения {filepath}: {e}[/bold red]")
        wait_and_exit()


def load_whitelist_sni(filepath: str = "whitelist_sni.txt") -> list:
    """Загружает список SNI для белого списка из файла."""
    path = get_resource_path(filepath)

    if not path.exists():
        console.print(f"[yellow]Файл {filepath} не найден, тест 4 недоступен.[/yellow]")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except Exception as e:
        console.print(f"[yellow]Ошибка чтения {filepath}: {e}[/yellow]")
        return []
