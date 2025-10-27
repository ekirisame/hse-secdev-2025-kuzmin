# DS - Отчёт «DevSecOps-сканы и харднинг»

> Этот файл - **индивидуальный**. Его проверяют по **rubric_DS.md** (5 критериев × {0/1/2} → 0-10).
> Подсказки помечены `TODO:` - удалите после заполнения.
> Все доказательства/скрины кладите в **EVIDENCE/** и ссылайтесь на конкретные файлы/якоря.

---

## 0) Мета

- **Проект (опционально BYO):** «учебный шаблон»
- **Версия (commit/date):** TODO: 2025-10-27
- **Кратко (1-2 предложения):** Сканируется на уязвимости Docker-образ nginx-flask-mysql, являющийся заменой образу веб-приложения, имеющего базу данных, бекенд и простой фронтенд, не использующий JS-фреймворки(https://github.com/docker/awesome-compose/tree/master/nginx-flask-mysql).

---

## 1) SBOM и уязвимости зависимостей (DS1)

- **Инструмент/формат:** Syft/Grype; CycloneDX
- **Как запускал:**

  ```bash
  syft dir:. -o cyclonedx-json > EVIDENCE/sbom-2025-27-10.json
  grype sbom:EVIDENCE/sbom-YYYY-MM-DD.json --fail-on high -o json > EVIDENCE/deps-2025-27-10.json
  ```

- **Отчёты:** `EVIDENCE/sbom-2025-27-10.json`, `EVIDENCE/deps-2025-27-10.json`
- **Выводы (кратко):** Была найдена одна High уязвимость во фреймворке Flask, связанная с раскрытием перманентной сессионной cookie из-за отсутствия заголовка Vary: Cookie.
- **Действия:** Уязвимость исправлена с помощью увеличения необходимой версии Flask: в Flask 2.2.5 она была исправлена.
- **Гейт по зависимостям:** Critical=0; High≤1

---

## 3) Policy (Container/IaC) (DS3)

### Вариант B - Policy / Container / IaC

- **Инструмент(ы):** trivy config
- **Как запускал:**

  ```bash
  trivy config . --severity HIGH,CRITICAL --exit-code 1 --format table > EVIDENCE/trivy-2025-27-10.txt
  ```

- **Отчёт(ы):** `EVIDENCE/trivy-2025-27-10.txt`
- **Выводы:** Было обнаружены ошибки конфигурации в исследуемом контейнере: и бекенд, и прокси были запущены в контейнерах от рута. Кроме того, в контейнере бекенда были нарушены правила работы с менеджером пакетов при установке зависимостей.

---

## 4) Харднинг (доказуемый) (DS4)

Отметьте **реально применённые** меры, приложите доказательства из `EVIDENCE/`.

- [x] **Контейнер non-root / drop capabilities** → Evidence: `EVIDENCE/backend-dockerfile-upd.Dockerfile, EVIDENCE/proxy-dockerfile-upd.Dockerfile`
- [ ] **Rate-limit / timeouts / retry budget** → Evidence: `EVIDENCE/load-after.png`
- [ ] **Input validation** (типы/длины/allowlist) → Evidence: `EVIDENCE/sast-YYYY-MM-DD.*#input`
- [ ] **Secrets handling** (нет секретов в git; хранилище секретов) → Evidence: `EVIDENCE/secrets-YYYY-MM-DD.*`
- [x] **HTTP security headers / CSP / HTTPS-only** → Evidence: `EVIDENCE/dummy-nginx-conf.txt`
- [ ] **AuthZ / RLS / tenant isolation** → Evidence: `EVIDENCE/rls-policy.txt`
- [ ] **Container/IaC best-practice** (минимальная база, readonly fs, …) → Evidence: `EVIDENCE/trivy-YYYY-MM-DD.txt#cfg`

> Для «1» достаточно ≥2 уместных мер с доказательствами; для «2» - ≥3 и хотя бы по одной показать эффект «до/после».

---

## 5) Quality-gates и проверка порогов (DS5)

- **Пороговые правила (словами):**  
  Примеры: «SCA: Critical=0; High≤1», «Trivy: Misconfigurations<=1».
- **Как проверяются:**   
  - Автоматически:  (скрипт/job, условие fail при нарушении)

    ```bash
    SCA: syft dir:. -o cyclonedx-json > EVIDENCE/formed-sbom.json | grype sbom:EVIDENCE/formed-sbom.json --fail-on high -o json > EVIDENCE/deps-2025-27-10.json
    Policy/IaC: trivy config --severity HIGH,CRITICAL --exit-code 1
    ```

---

## 6) Триаж-лог (fixed / suppressed / open)

| ID/Anchor       | Класс     | Severity | Статус     | Действие | Evidence                               | Ссылка на фикс/исключение         | Комментарий / owner / expiry |
|-----------------|-----------|----------|------------|----------|----------------------------------------|-----------------------------------|------------------------------|
| CVE-2023-30861   | SCA       | High     | fixed      | bump     | `EVIDENCE/requirements-new.txt`    | `commit abc123`                   | requirements.txt обновлены для использования версии Flask, где уязвимость была исправлена |
| POLICY-1        | Policy      | High   | fixed | bump   | `EVIDENCE/trivy-after.txt     | commit abc123   | Фикс работы в контейнере с бекендом под рутом |
| POLICY-2        | Policy      | High   | ignore | ignore   | `EVIDENCE/trivy-after.txt     | commit abc123   | Работа с пакетным менеджером ведется правильно - Trivy воспринимает apk как apk из Ubuntu, но это apk из Alpine Linux |
| POLICY-3        | Policy      | High   | fixed | bump   | `EVIDENCE/trivy-after.txt     | commit abc123   | Добавление флага --no-cache в пакетный менеджер для уменьшения размера образа |
| POLICY-4        | Policy      | High   | fixed | bump   | `EVIDENCE/trivy-after.txt     | commit abc123   | Фикс работы в контейнере с прокси под рутом |

> Для «2» по DS5 обязательно указывать **owner/expiry/обоснование** для подавлений.

---

## 7) Эффект «до/после» (метрики) (DS4/DS5)

| Контроль/Мера | Метрика                 | До   | После | Evidence (до), (после)                          |
|---------------|-------------------------|-----:|------:|-------------------------------------------------|
| Зависимости   | #Critical / #High (SCA) | 0 / 1 | 0 / 0| `EVIDENCE/deps-before.json`, `deps-after.json`  |
| Policy/IaC    | Violations              | 4 | 1     | `EVIDENCE/trivy-2025-10-27.txt`, `trivy-after.txt` |

---

## 8) Самооценка по рубрике DS (0/1/2)

- **DS1. SBOM и SCA:** [ ] 0 [ ] 1 [x] 2  
- **DS2. SAST + Secrets:** [x] 0 [ ] 1 [ ] 2  
- **DS3. DAST или Policy (Container/IaC):** [ ] 0 [x] 1 [ ] 2  
- **DS4. Харднинг (доказуемый):** [ ] 0 [x] 1 [ ] 2  
- **DS5. Quality-gates, триаж и «до/после»:** [ ] 0 [ ] 1 [x] 2  

**Итог DS (сумма):** 6/10
