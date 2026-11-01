# Resverse IA

Nota: Una vez instalado el uso es sencillo en tu ide de preferencia (lo probé en antigravity) pides que inicie el proyecto Resverse IA y que lo aplique en reto ejemplo (cambies el archivo exe, dll u otro o lo renombres a reto.dll o reto.exe) lo examinara y te dará un resumen ya lo dejo en tus manos como lo uses Guiño Guiño puedes decirle 
"Genera un plan que abarque todo y que la herramienta se encargue" te dará un montón de texto e información si no logras lo que quieres puede decirle "esta bien pero puede hacerlo mejor", lo dejo en tus manos. este repo fue creado con fines educativos basado en ingeniería inversa con ia  

Puente local entre **Ghidra**, un **modelo de IA local (Ollama)** y un **Patch Lab** con guardrails. La IA no recibe binarios crudos ni ejecuta acciones peligrosas: recibe *paquetes de evidencia* con IDs estables y responde con citas verificables. Para editar, el motor genera y valida candidatos deterministas; la IA solo elige uno y un humano aprueba el plan, que solo se aplica sobre **copias**.

```
binario ──> Ghidra headless/PyGhidra ──> export JSON
                                              │
                                     SQLite + FTS5 (índice local)
                                              │
                                     Evidence Packet (F:0x...)
                                              │
                                  Ollama (modelo local, 4–8 GB VRAM)
                                              │
                                  Validador de grounding
                                              │
                     respuesta/annotations ──┴──> Patch Plan ──> aprobación humana
                                                                      │
                                                             copia .patched + auditoría
                                                                      │
                                                                 rollback
```

## Requisitos

- Python 3.11+ (probado con 3.12.6 en Windows).
- Ghidra 11.3+ (probado con **Ghidra 12.1.4**) y **JDK 21+** (probado con JDK 25; Ghidra 12.1.4 declara mínimo 21).
- PyGhidra 3.x (`pip install pyghidra`; probado con 3.2.0) para analizar binarios.
- Ollama 0.40+ con un modelo local (probado con `qwen2.5-coder:7b-instruct-q4_K_M`).
- Opcional: `--export-json` permite trabajar con un export de Ghidra ya generado, sin instalar PyGhidra.
- REA es independiente: es una herramienta Rust con su propio MCP (`rea serve`), **no** un plugin de Ghidra. Resverse IA no la integra todavía; `doctor` la detecta si está en el PATH o si encuentra el ZIP en Descargas.

SQLite con FTS5 se usa si está disponible; si no, la búsqueda cae a `LIKE`.

## Instalación

```bash
cd "ruta/al/proyecto"
python -m venv .venv
.venv/Scripts/activate          # Windows
pip install -e .
pip install pyghidra            # opcional pero necesario para dll open sin --export-json
```

Sin instalar el paquete también funciona:

```bash
PYTHONPATH=src python -m reia --help
```

## Configurar Ghidra

1. Instala Ghidra 11.3 o superior (probado con 12.1.4) y un JDK 21 o superior.
2. Define `GHIDRA_INSTALL_DIR` apuntando a la carpeta que contiene `support/analyzeHeadless.bat`.

```bash
setx GHIDRA_INSTALL_DIR "C:\Tools\ghidra_12.1.4_PUBLIC"
```

`reia doctor` también busca Ghidra en `C:\ghidra*`, `C:\Program Files\ghidra*`, `~/ghidra*` y `~/Downloads/ghidra*`. También puedes pasar `--ghidra-home` a `dll open`.

## Configurar Ollama

```bash
ollama serve
ollama pull qwen2.5-coder:7b-instruct-q4_K_M
```

- GPU de 8 GB o menos: `qwen2.5-coder:7b-instruct-q4_K_M` (recomendado; probado con Ollama 0.40.13).
- GPU de 4 GB o menos: `qwen2.5-coder:3b`.
- El prompt usa `num_ctx=16384` y paquetes de evidencia compactos.
- Ollama escucha en `http://127.0.0.1:11434`; se puede cambiar con `OLLAMA_HOST`.
- En perfiles con la nube bloqueada (`malware`, `analysis`), `reia ask` se niega a usar un `OLLAMA_HOST` que no sea localhost. `ask --packet-only` sigue funcionando sin red.

## Verificar el entorno y conectar el IDE

```bash
reia --workspace "C:/reia/ws" doctor
reia --workspace "C:/reia/ws" config mcp
```

`doctor` comprueba Python, workspace, SQLite/FTS5, Ghidra, versión de Java frente a la versión de Ghidra, PyGhidra, REA y Ollama.

`config mcp` imprime el bloque `mcpServers` listo para pegar en Qoder, Antigravity o Claude. El archivo [AGENTS.md](AGENTS.md) describe al agente del IDE cómo usar las herramientas y qué límites respetar.

## Inicio rápido

```bash
# 1. Inicializar un workspace (por defecto ~/.reia; usa una ruta local)
reia --workspace "C:/reia/ws" init --profile ctf

# 2. Comprobar el entorno
reia --workspace "C:/reia/ws" doctor

# 3. Abrir y analizar un DLL/EXE/ELF con Ghidra
reia --workspace "C:/reia/ws" dll open "C:/retos/reto.dll"

#    O importar un export ya generado
reia --workspace "C:/reia/ws" dll open "C:/retos/reto.dll" --export-json export.json

# 4. Inspeccionar
reia --workspace "C:/reia/ws" dll info
reia --workspace "C:/reia/ws" dll exports
reia --workspace "C:/reia/ws" dll functions --query Validate
reia --workspace "C:/reia/ws" dll decompile --function Validate
reia --workspace "C:/reia/ws" dll strings --query key

# 5. Construir el paquete de evidencia para la IA
reia --workspace "C:/reia/ws" evidence --query Validate -o packet.json

# 6. Preguntar al modelo local
reia --workspace "C:/reia/ws" ask "¿Qué valida la función Validate?" --query Validate

#    Ver el paquete sin llamar a Ollama
reia --workspace "C:/reia/ws" ask "..." --query Validate --packet-only
```

### Patch Lab (solo copias, CTF/lab/binarios propios)

```bash
# Crear un plan: dirección virtual o file offset + bytes de reemplazo
reia --workspace "C:/reia/ws" patch plan --address 0x180001000 --bytes "90 90" --reason "NOP del chequeo en copia local del reto" --authorization "CTF local, binario propio"

# Aplicar sobre una COPIA (exige --approve)
reia --workspace "C:/reia/ws" patch apply patch_YYYYMMDD... --approve

# Ver planes
reia --workspace "C:/reia/ws" patch list --json

# Rollback de la copia parcheada
reia --workspace "C:/reia/ws" patch rollback patch_YYYYMMDD...
```

El original **nunca** se modifica. Cada `apply` crea en `patches/<plan_id>/`:

- `<nombre>.orig` — copia intacta
- `<nombre>.patched` — copia modificada
- `plan.json` — plan, hashes y autorización
- `diff.txt` — volcado hex anterior/nuevo

El Patch Lab verifica el hash del binario, que los bytes en el offset sigan siendo los originales, que el reemplazo tenga la misma longitud y que la escritura haya quedado exactamente como se esperaba. Si algo falla, elimina la copia parcheada y aborta. Todo queda en la tabla `audit`.

### Patch Advisor: la IA elige, el motor genera los bytes

La IA **no escribe instrucciones de parche ni bytes**. El motor decodifica la función con iced-x86, genera una lista cerrada de candidatos deterministas, los valida estáticamente y calcula el reemplazo exacto. El modelo local solo puede elegir un `candidate_id` de esa lista.

```bash
# 1. Ver candidatos de una función
reia --workspace "C:/reia/ws" patch candidates --function Validate

# 2. Construir un plan desde un candidato concreto
reia --workspace "C:/reia/ws" patch advise --function Validate \
  --candidate-id "0x180001000:return_constant:1" \
  --reason "devolver 1 en la copia del reto" \
  --authorization "CTF local, binario propio"

# 3. O pedir al modelo local que elija entre los candidatos
reia --workspace "C:/reia/ws" patch ai --function Validate \
  --intent "quiero que la función siempre devuelva 1" \
  --authorization "CTF local, binario propio"

# 4. Revalidar y aplicar sobre la copia, con aprobación humana
reia --workspace "C:/reia/ws" patch validate <PLAN_ID>
reia --workspace "C:/reia/ws" patch apply <PLAN_ID> --approve --authorization "CTF local, binario propio"
```

Candidatos actuales:

| Tipo | Efecto | Longitud |
|---|---|---|
| `return_constant` | `mov eax,imm32; ret` + relleno NOP hasta el primer `ret` | igual al span |
| `invert_branch` | invierte la condición del salto (`je` ↔ `jne`, etc.) | igual |
| `skip_call` | sustituye un `call` directo por NOPs | igual |
| `nop_instruction` | convierte una instrucción concreta en NOPs | igual |

El resultado de `patch advise`/`patch ai` es directamente accionable: muestra archivo, dirección, offset, bytes originales, bytes nuevos, validación y los comandos exactos de validar/aplicar/revertir. Nada se aplica automáticamente. Si la validación estática falla, `apply` rechaza el plan.

## Perfiles

| Perfil | Análisis | Parchear copias | Ejecutar | Nube / MCP externo |
|---|---|---|---|---|
| `ctf` | sí | sí, con autorización | sandbox (no implementado) | permitido con redacción |
| `own` | sí | sí, con autorización | sandbox | permitido con redacción |
| `interop` | sí | sí, con permiso explícito | sandbox | permitido con redacción |
| `malware` | sí, solo local | **no** | **no** | **bloqueado** |
| `analysis` | sí | **no** | **no** | permitido con redacción |

El perfil `malware` se niega a inicializarse dentro de OneDrive salvo `--allow-onedrive`. Mantén muestras y proyectos de malware fuera de carpetas sincronizadas.

## MCP

El servidor MCP usa stdio y no depende del SDK oficial.

```bash
reia --workspace "C:/reia/ws" mcp
```

Para generar el bloque de configuración del cliente:

```bash
reia --workspace "C:/reia/ws" config mcp
```

Configuración típica en un cliente MCP (Qoder, Antigravity, Claude Desktop, etc.):

```json
{
  "mcpServers": {
    "resverse-ia": {
      "command": "reia",
      "args": ["--workspace", "C:/reia/ws", "mcp"]
    }
  }
}
```

Si no instalaste el paquete:

```json
{
  "mcpServers": {
    "resverse-ia": {
      "command": "python",
      "args": ["-m", "reia", "--workspace", "C:/reia/ws", "mcp"],
      "env": { "PYTHONPATH": "C:/ruta/al/proyecto/src" }
    }
  }
}
```

Herramientas expuestas: `programs_list`, `program_info`, `functions_search`, `function_get`, `dll_exports`, `dll_imports`, `strings_search`, `evidence_pack`, `patch_candidates`, `patch_build`, `patch_validate`, `patch_plan`, `patch_list`, `policy_show`.

`patch_candidates` lista los candidatos deterministas; `patch_build` crea un plan a partir de un `candidate_id`; `patch_plan` permite un plan manual; `patch_validate` revalida contra el archivo actual. **No existe** una herramienta MCP para aplicar parches. La aplicación exige el CLI y `--approve`. Con perfil `malware`, el servidor MCP se niega a arrancar salvo `--allow-external-client`, y aun así está pensado solo para clientes que corran en la misma máquina.

## Grounding

Cada respuesta del modelo se valida contra el paquete de evidencia:

- direcciones `0x...` que no aparecen en la evidencia → warning;
- IDs `F:0x...` inventados → warning;
- claims sin cita de evidencia → warning;
- annotations que apuntan a evidencia inexistente → warning.

Los warnings se muestran en stderr y se guardan con la sesión en SQLite. No se confía en la respuesta del modelo como verdad: es una hipótesis citada.

## Estructura

```
AGENTS.md           reglas y flujo para el agente del IDE
src/reia/
  cli.py            CLI y comandos
  mcp_server.py     servidor MCP stdio
  ghidra_export.py  exportador PyGhidra
  binary.py         parseo PE/ELF y dirección → offset
  store.py          SQLite/FTS5, evidence packets, auditoría
  patch.py          Patch Lab (plan/apply/rollback)
  patch_advisor.py  candidatos deterministas y validación estática
  grounding.py      validador de citas y direcciones
  ollama.py         cliente local
  policy.py         perfiles y límites
tests/
  test_core.py
  fixtures/sample_export.json
```

## Pruebas

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Las 45 pruebas construyen un PE mínimo con código x86-64 real, importan el fixture, verifican búsqueda/FTS, paquetes de evidencia, grounding, MCP, el ciclo completo de parche (rollback, plan obsoleto, longitud incorrecta, hash del original intacto) y el Patch Advisor (candidatos deterministas, bytes esperados, validación, rechazo de planes inválidos y selección IA simulada).

## Límites deliberados

- No hay jailbreak, modo “sin restricciones” ni evasión de filtros.
- No se parchea software de terceros en producción, DRM, licencias, anti-cheat ni malware.
- No se ejecuta el binario analizado; `execution: sandbox-only` es una intención de diseño, no un sandbox implementado todavía.
- El modelo local sigue sujeto a la política del proyecto: privacidad no significa ausencia de límites.
- El Patch Lab reemplaza bytes de **igual longitud**; el Advisor genera secuencias x86/x64 dentro del mismo span y rellena con NOP, pero no reubica código.
- La validación del Advisor es **estática** (decodificación, sección ejecutable, límites, bytes y destino de saltos); no emula el binario ni ejecuta el DLL para comprobar que sigue funcionando.
- El Advisor solo soporta x86/x64 (PE/ELF) y cuatro tipos de edición; funciones con thunks, imports o firmas no soportadas no generan candidatos.
- Los valores de retorno constantes se limitan a 32 bits (EAX).
- No escribe anotaciones (renombres, comentarios, tipos) de vuelta en el proyecto de Ghidra.
- Mach-O se detecta pero no tiene mapeo dirección → offset; usa `--file-offset`.
- El código del proyecto puede vivir en OneDrive; las muestras y proyectos de malware, no.
- REA no está integrado; si se usa, se ejecuta como MCP independiente con `rea serve`.

## Estado

Implementado y probado localmente: CLI, store/FTS, evidence packets, grounding, MCP, parseo PE/ELF, Patch Lab con auditoría y rollback, Patch Advisor determinista (candidatos + validación + `patch ai`), y el puente real **Ghidra 12.1.4 + PyGhidra 3.2.0 + JDK 25** sobre `C:\Windows\System32\version.dll` (72 funciones, 35 exports, 81 imports, 154 strings, decompilación y paquete de evidencia).

También probado de extremo a extremo con **Ollama 0.40.13 + qwen2.5-coder:7b-instruct-q4_K_M**: el modelo eligió el candidato correcto para dos intenciones distintas, el motor generó los bytes exactos, el plan se validó y se aplicó solo a una copia.

Pendiente: emulación/ejecución sandbox para comprobar el comportamiento del DLL parcheado, write-back de anotaciones a Ghidra e integración con REA.
