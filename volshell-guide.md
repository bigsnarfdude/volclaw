# Volshell — Interactive Memory Analysis Guide

Volshell is Volatility 3's interactive shell for hands-on memory exploration. It provides a Python REPL with direct access to memory layers, symbol tables, and all Volatility internals.

## Starting Volshell

```bash
# Generic mode (limited, no symbols)
volshell -f <image>

# Windows mode (full Windows symbol support)
volshell -f <image> -w

# Linux mode
volshell -f <image> -l

# macOS mode
volshell -f <image> -m

# With a script to auto-execute
volshell -f <image> -w --script myscript.py
```

The mode determines which OS-specific commands and symbol tables are available. Always specify the OS if you know it.

## Prompt & Context

When Volshell starts, the prompt shows the current layer:

```
Volshell (Volatility 3 Framework) 2.x.x
Current Layer : primary
(primary) >>>
```

Key context variables:
- `self.current_layer` — Name of the active memory layer
- `self.current_symbol_table` — Active symbol table
- `self.current_kernel_name` — Kernel module name
- `self.context` — The Volatility context object

## Core Commands

### Getting Help

```python
>>> help()                    # List all available commands
>>> help(display_bytes)       # Help on a specific command
```

### Memory Reading

```python
# Display hex bytes at an offset
>>> db(0x7FFE0000)                     # 128 bytes from offset (alias for display_bytes)
>>> display_bytes(0x7FFE0000, count=256)  # Custom byte count

# Display as words (2 bytes), doublewords (4), quadwords (8)
>>> dw(0x7FFE0000)                     # display_words
>>> dd(0x7FFE0000)                     # display_doublewords
>>> dq(0x7FFE0000)                     # display_quadwords
```

### Disassembly

```python
# Disassemble instructions at an address
>>> dis(0x7FFE0000)                    # alias for disassemble
>>> disassemble(0x7FFE0000, count=20)  # custom instruction count
```

### Symbol & Type Inspection

```python
# Search for symbols by name
>>> ds("Nt")                           # alias for display_symbols
>>> display_symbols("PsActive")       # find symbols containing "PsActive"

# Display a kernel structure at an offset
>>> dt("_EPROCESS", 0xFFFF8A0123456789)    # alias for display_type
>>> display_type("_KTHREAD", 0xFFFF...)
```

### Layer Management

```python
# Change active layer
>>> cl("primary")                      # alias for change_layer
>>> change_layer("memory_layer")

# Create a new constructable (layer or symbol table)
>>> cc(SomeLayerClass, on_top_of='primary', ...)  # create_configurable
```

### Running Plugins Interactively

```python
# Import and run a plugin
>>> from volatility3.plugins.windows import pslist
>>> display_plugin_output(pslist.PsList)

# Check plugin requirements
>>> pslist.PsList.get_requirements()

# Run with specific options
>>> from volatility3.plugins.windows import netscan
>>> display_plugin_output(netscan.NetScan)
```

### Process Context (OS-Specific)

```python
# Windows: get a process object
>>> proc = get_process(1234)           # by PID
>>> proc.ImageFileName
>>> proc.UniqueProcessId

# Linux: change task context
>>> ct(1234)                           # change_task by PID
>>> change_task(1234)
```

## Scripting Volshell

You can write scripts that execute in the Volshell context:

```python
# save as dump_region.py
# Run with: volshell -f image -w --script dump_region.py

layer = self.context.layers[self.current_layer]
with open('output.bin', 'wb') as fp:
    for offset in range(0x10000, 0x20000, 0x1000):
        data = layer.read(offset, 0x1000, pad=True)
        fp.write(data)
print(f"[+] Dumped 0x10000 bytes to output.bin")
```

Execute scripts at runtime:
```python
>>> rs("dump_region.py")               # alias for run_script
>>> run_script("dump_region.py")
```

## Practical Examples

### Walk the Process List Manually

```python
>>> from volatility3.plugins.windows import pslist
>>> for proc in pslist.PsList.list_processes(
...     context=self.context,
...     layer_name=self.current_layer,
...     symbol_table=self.current_symbol_table):
...     print(f"PID={proc.UniqueProcessId} Name={proc.ImageFileName}")
```

### Read a Specific Kernel Structure

```python
# Read KUSER_SHARED_DATA (always at 0x7FFE0000 in Windows)
>>> dt("_KUSER_SHARED_DATA", 0xFFFFF78000000000)
```

### Extract Bytes from a Memory Region

```python
>>> layer = self.context.layers[self.current_layer]
>>> data = layer.read(0x1000, 0x100, pad=True)
>>> import binascii
>>> print(binascii.hexlify(data[:32]))
```

### Breakpoints (Debugging)

```python
# Set a breakpoint
>>> breakpoint(0x7FFE0000)
>>> breakpoint(0x7FFE0000, layer_name="primary")

# List breakpoints
>>> breakpoint_list()

# Clear breakpoints
>>> breakpoint_clear()
>>> breakpoint_clear(offset=0x7FFE0000)
```

## Tips

- Volshell gives you **full Python access** — import any library, write loops, define functions
- Use `self.context` to access any Volatility component programmatically
- Combine with `display_plugin_output()` for quick one-off plugin runs
- Script repetitive tasks and execute with `--script` for reproducibility
- Output to files for documentation: `with open('out.txt', 'w') as f: ...`
