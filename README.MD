# VulnLab (MVP)

Умышленно уязвимое приложение для тренировки пентеста.
Только локальный запуск. Не выставлять в интернет.

## Правила
- Тестируем ТОЛЬКО этот контейнер.
- Никаких атак на хост, docker daemon, соседние сервисы.
- Данные синтетические, можно ломать.
- Reset: `curl -X POST http://127.0.0.1:8000/reset`

## Запуск
    docker compose up --build

Открыть: http://127.0.0.1:8000

## Учётные данные (seed)
| user  | password  | role  |
|-------|-----------|-------|
| admin | admin123  | admin |
| alice | password1 | user  |
| bob   | password2 | user  |

## Задания и флаги

1. SQLi в /login — залогиниться как admin без пароля.
2. UNION SQLi в /search — вытащить содержимое `notes`.
   Флаг: `FLAG{idor_admin_note}` (можно и через #3).
3. IDOR /profile/{id} — прочитать заметку admin (id=1).
4. Path traversal /files — прочитать `/data/secret.txt`.
   Флаг: `FLAG{path_traversal_master}`.
5. Command injection /ping — выполнить `id` или `cat /etc/passwd`.
6. JWT forgery — подделать токен с `role=admin` и получить /admin.
   Флаг: `FLAG{jwt_forged_admin}`.
7. Stored XSS /comments — выполнить JS в браузере (проверять в DevTools).
8. Reflected XSS /search?q=.
9. CSRF /settings/email — сменить email без ведома пользователя
   (например, через `<img src="http://127.0.0.1:8000/settings/email?email=evil@x">`).

## Инструменты
- curl / Burp Suite / OWASP ZAP
- sqlmap (по /search и /login)
- jwt_tool (по JWT forgery)
- браузер DevTools (XSS)
