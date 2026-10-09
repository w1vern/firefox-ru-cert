# Сертификат Минцифры только для нужных доменов

Скрипты выпускают пару сертификатов для Firefox. С ними корень Минцифры (Russian Trusted Root CA) работает только для доменов из твоего списка. Ставить его в систему или пользоваться Яндекс Браузером не нужно.

## Как работает

Корень Минцифры в Firefox не ставится. Вместо него ставятся два сертификата:

- `my_ca.crt` — свой корневой CA, ограниченный зонами (`ru`, ...). Только ему Firefox доверяет напрямую.
- `cross.crt` — кросс-сертификат на ключ Минцифры, подписанный `my_ca`, с **Name Constraints** по списку доменов.

Цепочка выглядит так: сайт → Russian Trusted Sub CA → `cross.crt` → `my_ca.crt`. Сертификат Минцифры для домена не из списка Firefox отвергнет (`SEC_ERROR_CERT_NOT_IN_NAME_SPACE`).

## Использование

Нужен `russian_trusted_root_ca.cer` с [gosuslugi.ru/crt](https://www.gosuslugi.ru/crt), положи его рядом со скриптами.

```sh
# 1. Перечисли сайты в sites.txt, затем собери домены из их сертификатов
uv run --with cryptography collect_domains.py

# 2. Проверь и поправь domains.txt

# 3. Выпусти сертификаты (--save-key сохранит зашифрованный ключ CA,
#    тогда при следующих запусках перевыпускается только cross.crt)
uv run --with cryptography issue_certs.py
```

## Установка в Firefox

Settings → Privacy & Security → Certificates → View Certificates → **Authorities**:

1. Удали старые «My RU Constraint CA» и «Russian Trusted Root CA», если они есть.
2. Импортируй `my_ca.crt` с галкой «Trust this CA to identify websites».
3. Импортируй `cross.crt` **без галок**.
4. Перезапусти Firefox.

Чтобы проверить, что ограничения работают, убери домен из списка и перевыпусти сертификаты. Этот сайт должен перестать открываться.

## Ограничения

- Для доменов из списка Минцифры по-прежнему может выпустить поддельный сертификат.
- Не храни `my_ca.key` в репозитории.