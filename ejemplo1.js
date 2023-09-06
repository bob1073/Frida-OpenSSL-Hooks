// Nombre de la funcion a hookear
var functionName = 'sumar';

// Obtenemos su direccion de memoria
var address = DebugSymbol.fromName("sumar").address;
console.log(address)
// Carga el modulo donde se encuentra la dirección de memoria
var moduleName = DebugSymbol.fromAddress(address).moduleName;

if (address != null) {
    console.log("Address found: " + address)
    console.log('[!] Hooking: ' + functionName /*+ ' @ 0x' + address.toString(16)*/);
    try {
        Interceptor.attach(address, {
            // Qué hacer a la entrada de la función
            onEnter: function(args) {
                // sumar(a, b)

                // Obtenemos los argumentos de la función y los mostramos
                var a = args[0];
                var b = args[1];
                console.log(functionName + "() [" + moduleName + "]");
                console.log('a: ' + a.toInt32());
                console.log('b: ' + b.toInt32());
            },
            // Qué hacer a la salida de la función
            onLeave: function(result) {
                console.log("Suma: " + result.toInt32());
            },
        });
    }
    catch (error) {
        console.error(error);
    }
}
else
{
    console.log("No se pudo obtener la direccion de memoria")
}