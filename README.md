# self_map
Self DLL injection with export lookup

```c++
//create class instance
//buffer is a pointer to our image
self_map* mapper = new self_map(buffer);

//map the image
NTSTATUS status = mapper->map();

//make sure it succeed
if (NT_SUCCESS(status))
{
    //find a function
    func_ func = reinterpret_cast<func_>(mapper->export_lookup("func"));
    
    //make sure it was found
    if (func)
    {
      //do stuff
    }
}

//free memory
mapper->free_memory();
delete mapper;
```
