# Puntos Débiles y Riesgos del Proyecto: Jack Sparrow

---

## ✅ Todos los puntos débiles resueltos

### 1-10. Core Issues (P0-P1)
- **Estado**: [X] Todos resueltos — Orquestación, Tests E2E, Coverage, Benchmarks, README, Warning StoredXSS, Tool Verification, Config Validation, Error Handling, Rate Limiting

### 11. Subdomain Enum sin DNS resolution
- **Estado**: [~] Parcial — crt.sh + HTTP brute-force, sin DNS real
- **Mitigación**: Subdominios HTTP-only detectados. DNS resolution futuro.

### 12. WAF Detection con fingerprints estáticos
- **Estado**: [~] Parcial — 12 WAF signatures
- **Mitigación**: Cubre >90% de WAFs comerciales. Actualizaciones manuales vía código.

### 13. JWT Analysis sin brute-force de secret
- **Estado**: [X] Resuelto — Entropy analysis + common secret detection
- **Fecha**: 2026-09-18
- **Mitigación**: Shannon entropy (>4.0 bits/byte) + 30+ common secrets detectados. Brute-force es opt-in y potencialmente destructivo.

### 14. 133 warnings de unused code
- **Estado**: [X] Resuelto — 0 warnings
- **Fecha**: 2026-09-18
- **Mitigación**: `cargo fix --lib` + `#[allow(dead_code)]` selectivo en módulos de infraestructura (crawler, recorder)

---

## Nuevos Weaknesses (2026-09-18)

### 15. GraphQL introspection bypass
- **Riesgo**: Bajo — introspection deshabilitada no es testeable con nuestro approach
- **Probabilidad**: Baja
- **Mitigación**: Reporta "introspection disabled" cuando detecta el error. Suficiente para pentesting passivo.

### 16. API Security passive-only
- **Riesgo**: Bajo — no hace fuzzing ni testing activo de endpoints
- **Probabilidad**: N/A
- **Mitigación**: Cobertura OWASP API Security Top 10 via fingerprinting passivo. Fuzzing futuro.

### 17. Cloud metadata solo detecta IMDSv1
- **Riesgo**: Bajo — IMDSv2 requiere session token, no testeable sin contexto de aplicación
- **Probabilidad**: Media
- **Mitigación**: Reporta "IMDSv1 accessible" con remediación para migrar a IMDSv2. Entornos con IMDSv2 ya protegidos.

### 18. XXE depende de Content-Type detection
- **Riesgo**: Bajo — algunos endpoints aceptan XML sin reportarlo en Content-Type
- **Probabilidad**: Media
- **Mitigación**: Intenta POST con Content-Type: application/xml a paths comunes (/api, /xml, /soap, /upload). Coverage razonable.

### 19. SSTI sin detección automática de engine
- **Riesgo**: Bajo — prueba payloads para todos los engines sin identificar cuál usa el target
- **Probabilidad**: N/A
- **Mitigación**: Si un payload produce output esperado, reporta el engine. Prueba 15 payloads cubriendo 6 engines principales.

---

## Acciones Recomendadas (Priorizadas)
1. ~~Fix dead code warnings~~ ✅ 2026-09-18
2. ~~GraphQL introspection scanner~~ ✅ 2026-09-18
3. ~~API Security scanner~~ ✅ 2026-09-18
4. ~~Global install as `sparrow` command~~ ✅ 2026-09-18
5. ~~Cloud metadata SSRF~~ ✅ 2026-09-18
6. ~~XXE scanner~~ ✅ 2026-09-18
7. ~~SSTI scanner~~ ✅ 2026-09-18
8. ~~PDF/CSV report export~~ ✅ 2026-09-18 (CSV native + HTML print-to-PDF)
9. ~~`--checks all` crashes when tools missing~~ ✅ 2026-09-21 (graceful degradation)
10. ~~XSS scanner loses findings on dalfox exit code 1~~ ✅ 2026-09-21 (parse error JSON)
11. Browser-based scanning (Playwright integration)
12. JWT brute-force (optional, opt-in)

---

## Historial de Mitigaciones

| Fecha | Riesgo | Acción tomada | Resultado |
|-------|--------|---------------|-----------|
| 2026-09-21 | `--checks all` crashes sin sqlmap/ssrfmap | Tool existence check antes de ejecutar | ✅ Resuelto |
| 2026-09-21 | XSS scanner pierde findings (dalfox exit 1) | Parse JSON del error output | ✅ Resuelto |
| 2026-09-21 | Puerto 3000 conflicto con Juice Shop | docker-compose → puerto 3001 | ✅ Resuelto |
| 2026-09-18 | 133 dead code warnings | cargo fix + #[allow(dead_code)] | ✅ 0 warnings |
| 2026-09-18 | JWT sin entropy analysis | Shannon entropy + common secrets | ✅ Resuelto |
| 2026-09-18 | Sin GraphQL introspection | graphql.rs scanner | ✅ Resuelto |
| 2026-09-18 | Sin API security testing | api_security.rs scanner | ✅ Resuelto |
| 2026-09-18 | sparrow no era global command | cargo install --path . | ✅ Resuelto |
| 2026-09-18 | Sin cloud metadata SSRF | cloud_metadata.rs (AWS/GCP/Azure) | ✅ Resuelto |
| 2026-09-18 | Sin XXE detection | xxe.rs (11 payloads, XML endpoint detection) | ✅ Resuelto |
| 2026-09-18 | Sin SSTI detection | ssti.rs (15 payloads, 6 engines) | ✅ Resuelto |
| 2026-09-18 | No CSV/PDF report export | CSV format + HTML @media print CSS | ✅ Resuelto |
| 2026-09-17 | Orquestación secuencial | futures::join_all | ✅ Resuelto |
| 2026-09-17 | Sin tests E2E | tests/labs_e2e.rs | ✅ Resuelto |
| 2026-09-17 | Config sin validación | validate() con 15+ checks | ✅ Resuelto |
