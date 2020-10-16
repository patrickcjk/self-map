# self_map
Self DLL injection with export lookup

```c++
self_map* mapper = new self_map(buffer);

NTSTATUS status = mapper->map();
if (NT_SUCCESS(status))
{
    func_ func = reinterpret_cast<func_>(mapper->export_lookup("func"));
    if (map_drv)
    {
      //
    }
}

mapper->free_memory();
```
