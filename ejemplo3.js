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

function EVP_EncryptUpdate() {
    var name = 'EVP_EncryptUpdate';
        var address = Module.findExportByName(null, name);

        if(address == null)
        {
            console.log("Function " +  name + "() not found!");
        }
        else
        {
            var moduleName = DebugSymbol.fromAddress(address).moduleName;
            console.log('[!] Hooking: ' + name + ' @ 0x' + address.toString(16));
            try {
                Interceptor.attach(address, {

                    onEnter: function(args) {
                        console.log(name + "() [" + moduleName + "]");

                        // int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                        // int *outl, const unsigned char *in, int inl)

                        this.out = args[1];
                        this.outl = args[2];
                        this.in = args[3];
                        this.inl = args[4];
                    },

                    onLeave: function(result) {
                        console.log(utils.colors.green('Message to encrypt: ' + 
                            hex2a(hex(this.in.readByteArray(this.inl.toInt32()))) + ' Size: ' + this.inl.toInt32()));
                        console.log(utils.colors.green('Encrypted message: ' + 
                            hex(this.out.readByteArray(this.outl.readPointer().toInt32())))); 
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
};

function hex(arrayBuffer)
{
    return Array.from(new Uint8Array(arrayBuffer))
        .map(n => n.toString(16).padStart(2, "0"))
        .join("");
};

function hex2a(hex) 
{
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}  

EVP_EncryptUpdate();