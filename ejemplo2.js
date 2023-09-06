// Colores en consola
const utils = {
	colors: {
		red: function(string) {
			return '\x1b[31m' + string + '\x1b[0m';
		},

		green: function(string) {
			return '\x1b[32m' + string + '\x1b[0m';
		},
	},

    backtrace: function(context) {
        return 'Backtrace:\n' + Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n';
    }
}

var functionName = 'EVP_MD_get0_name';
var address = Module.findExportByName(null, functionName);

if(address == null)
{
    console.log("Function " +  functionName + "() not found!");
}
else
{
    var moduleName = DebugSymbol.fromAddress(address).moduleName;
    console.log('[!] Hooking: ' + functionName + ' @ 0x' + address.toString(16));
        try {
        Interceptor.attach(address, {
            onLeave: function(result) {
                // const char *EVP_MD_get0_name(const EVP_MD *md)
                console.log(utils.colors.green('Hash Type: ' + Memory.readUtf8String(result)));
            },
        });
    }
    catch (error) {
        console.error(error);
    }
}
