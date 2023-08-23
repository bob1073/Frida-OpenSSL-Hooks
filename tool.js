// Console log colors
const utils = {
	colors: {
		red: function(string) {
			return '\x1b[31m' + string + '\x1b[0m';
		},

		green: function(string) {
			return '\x1b[32m' + string + '\x1b[0m';
		},

		blue: function(string) {
			return '\x1b[34m' + string + '\x1b[0m';
		},

		cyan: function(string) {
			return '\x1b[36m' + string + '\x1b[0m';
		},
	},

    backtrace: function(context) {
        return 'Backtrace:\n' + Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n';
    }
}

// OpenSSL function hooks
function hooks() {

    // EC_KEY_generate_key
    (function() {
        var name = 'EC_KEY_generate_key';
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

                        // int EVP_Digest(const void *data, size_t count, unsigned char *md,
                        // unsigned int *size, const EVP_MD *type, ENGINE *impl)

                        // Se puede sacar tipo de hash?

                        this.key = args[0];
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'key=' + this.args[0] + ') = '  
                                               + result);
                        
                        console.log(utils.colors.green('Key: ' + Memory.readUtf8String(this.key)));
                        console.log(utils.colors.green('Success: ' + (result === 1) ? 'True' : 'False'));
                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                        
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();


    // EVP_ChiperInit_ex
    (function() {
		var name = 'EVP_ChiperInit_ex';
        var address = Module.findExportByName(null, name);

        if (address == null)
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
                        
                        // int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        // ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc)
                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);
                        this.args.push(args[3]);
                        this.args.push(args[4]);
                        this.args.push(args[5]);
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'ctx=' + this.args[0] + ', ' 
                                               + 'type=' + this.args[1] + ', ' 
                                               + 'impl=' + this.args[2] + ', ' 
                                               + 'key=' + this.args[3] + ', '
                                               + 'iv=' + this.args[4] + ', ' 
                                               + 'enc=' + this.args[5] + ') = ' 
                                               + result);
                        if(this.args[5] == 1)
                        {
                            console.log(utils.colors.green("Encrypting..."))
                        }
                        else
                        {
                            console.log(utils.colors.green("Decrypting..."))
                        }
                        console.log(utils.colors.green)
                        console.log(utils.colors.green("Key: " + Memory.readUtf8String(args[3])))
                        console.log(utils.colors.green("IV: " + Memory.readUtf8String(args[4])))

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    }
                });
            }
            catch (error) {
                console.error(error);
            }
        }
	})();


    // EVP_EncryptInit_ex
    (function() {
        var name = 'EVP_EncryptInit_ex';
        var address = Module.findExportByName(null, name);

        if (address == null)
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

                        // int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        // ENGINE *impl, const unsigned char *key, const unsigned char *iv)
                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);
                        this.args.push(args[3]);
                        this.args.push(args[4]);
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'ctx=' + this.args[0] + ', ' 
                                               + 'type=' + this.args[1] + ', ' 
                                               + 'impl=' + this.args[2] + ', ' 
                                               + 'key=' + this.args[3] + ', '
                                               + 'iv=' + this.args[4] + ') = ' 
                                               + result);
                       
                        console.log(utils.colors.green("Key: " + Memory.readUtf8String(args[3])));
                        console.log(utils.colors.green("IV: " + Memory.readUtf8String(args[4])));

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    }
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_DecryptUpdate
    (function() {
        var name = 'EVP_DecryptUpdate';
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

                        // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                        // int *outl, const unsigned char *in, int inl)

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);
                        this.args.push(args[3]);
                        this.args.push(args[4]);

                        
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'ctx=' + this.args[0] + ', ' 
                                               + 'out=' + this.args[1] + ', ' 
                                               + 'outl=' + this.args[2] + ', ' 
                                               + 'in=' + this.args[3] + ', '
                                               + 'inl=' + this.args[4] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Encrypted message: ' + hex(this.args[3].readByteArray(this.args[4].toInt32())) + ' Len: ' + this.args[4].toInt32()));
                        console.log(utils.colors.green('Decrypted message: ' + hex(this.args[1].readByteArray(this.args[2].readPointer().toInt32())) + 'Len: ' + this.args[2].toInt32())); 

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_EncryptUpdate
    (function() {
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

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);
                        this.args.push(args[3]);
                        this.args.push(args[4]);

                        
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'ctx=' + this.args[0] + ', ' 
                                               + 'out=' + this.args[1] + ', ' 
                                               + 'outl=' + this.args[2] + ', ' 
                                               + 'in=' + this.args[3] + ', '
                                               + 'inl=' + this.args[4] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Message to encrypt: ' + hex(this.args[3].readByteArray(this.args[4].toInt32())) + ' Len: ' + this.args[4].toInt32()));
                        console.log(utils.colors.green('Encrypted message: ' + hex(this.args[1].readByteArray(this.args[2].readPointer().toInt32())))); 

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_Digest
    (function() {
        var name = 'EVP_Digest';
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

                        // int EVP_Digest(const void *data, size_t count, unsigned char *md,
                        // unsigned int *size, const EVP_MD *type, ENGINE *impl)

                        // Se puede sacar tipo de hash?

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);
                        this.args.push(args[3]);
                        this.args.push(args[4]);
                        this.args.push(args[5]);

                        
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'data=' + this.args[0] + ', ' 
                                               + 'count=' + this.args[1] + ', ' 
                                               + 'md=' + this.args[2] + ', ' 
                                               + 'size=' + this.args[3] + ', '
                                               + 'type=' + this.args[4] + ', '
                                               + 'impl=' + this.args[5] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Data to hash: ' + Memory.readUtf8String(this.args[0])) + ' Len: ' + this.args[1].toInt32());
                        console.log(utils.colors.green('Hash Value: ' + Memory.readUtf8String(this.args[2])) + ' Len: ' + Memory.readPointer().toInt32());

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_MD_get0_name
    (function() {
        var name = 'EVP_MD_get0_name';
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

                        // const char *EVP_MD_get0_name(const EVP_MD *md)

                        this.md = args[0];          
                    },

                    onLeave: function(result) {
                        console.log(name + '(' 
                                               + 'md=' + this.md + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Hash Type: ' + Memory.readUtf8String(result)));

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_PKEY_derive
    (function() {
        var name = 'EVP_PKEY_derive';
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

                        // int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);      
                    },

                    onLeave: function(result) {
                        console.log(name + '(' 
                                               + 'md=' + this.md + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Hash Type: ' + Memory.readUtf8String(result)));

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_PKEY_get_octet_string_param
    (function() {
        var name = 'EVP_PKEY_get_octet_string_param';
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

                        // int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name,
                        // unsigned char *buf, size_t max_buf_sz,
                        // size_t *out_len)
                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);
                        this.args.push(args[3]);
                        this.args.push(args[4]);      
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'pkey=' + this.args[0] + ', ' 
                                               + 'key_name=' + this.args[1] + ', ' 
                                               + 'buf=' + this.args[2] + ', ' 
                                               + 'max_buf_sz=' + this.args[3] + ', '
                                               + 'out_len=' + this.args[4] + ') = ' 
                                               + result);
                        
                        if(result) {
                            console.log(utils.colors.green('Success, pkey octet: ' + Memory.readUtf8String(this.args[2])));
                        }
                        else
                        {
                            console.log(utils.colors.green('Unable to get pkey octet'));
                        }

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_PKEY_keygen
    (function() {
        var name = 'EVP_PKEY_keygen';
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

                        // int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);    
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'ctx=' + this.args[0] + ', ' 
                                               + 'ppkey=' + this.args[1] + ') = ' 
                                               + result);
                        
                        if(result) {
                            console.log(utils.colors.green('Success, generated key: ' + Memory.readUtf8String(this.args[1])));
                        }
                        else
                        {
                            console.log(utils.colors.green('Unable to generate key.'));
                        }

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // EVP_PKEY_Q_keygen 
    (function() {
        var name = 'EVP_PKEY_Q_keygen';
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

                        // EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                        // const char *type, ...);

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);   
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'libctx=' + this.args[0] + ', ' 
                                               + 'propq=' + this.args[1] + ', ' 
                                               + 'type=' + this.args[2] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Quick generated key: ' + Memory.readUtf8String(result)));

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // PKCS5_PBKDF2_HMAC
    (function() {
        var name = 'PKCS5_PBKDF2_HMAC';
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

                        // int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                        // const unsigned char *salt, int saltlen, int iter,
                        // const EVP_MD *digest,
                        // int keylen, unsigned char *out);

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);   
                        this.args.push(args[3]);
                        this.args.push(args[4]);
                        this.args.push(args[5]);
                        this.args.push(args[6]);
                        this.args.push(args[7]);
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'pass=' + this.args[0] + ', ' 
                                               + 'passlen=' + this.args[1] + ', ' 
                                               + 'salt=' + this.args[2] + ', ' 
                                               + 'saltlen=' + this.args[3] + ', ' 
                                               + 'iter=' + this.args[4] + ', ' 
                                               + 'digest=' + this.args[5] + ', ' 
                                               + 'keylen=' + this.args[6] + ', ' 
                                               + 'out=' + this.args[7] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Password: ' + Memory.readUtf8String(this.args[0])) + ' Len: ' + this.args[1]);
                        console.log(utils.colors.green('Salt: ' + Memory.readUtf8String(this.args[2])) + ' Len: ' + this.args[3]);
                        console.log(utils.colors.green('Iteration count: ' + this.args[4]));
                        console.log(utils.colors.green('Generated key: ' + Memory.readUtf8String(this.args[7])) + ' Len: ' + this.args[6]);

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // RAND_bytes
    (function() {
        var name = 'RAND_bytes';
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

                        // int RAND_bytes(unsigned char *buf, int num);

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'buf=' + this.args[0] + ', '  
                                               + 'num=' + this.args[1] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Random bytes: ' + Memory.readUtf8String(this.args[0])) + ' Len: ' + this.args[1]);

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // RAND_bytes_ex
    (function() {
        var name = 'RAND_bytes_ex';
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

                        // int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                        // unsigned int strength);

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                        this.args.push(args[2]);
                        this.args.push(args[3]);
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'ctx=' + this.args[0] + ', ' 
                                               + 'buf=' + this.args[1] + ', ' 
                                               + 'num=' + this.args[2] + ', ' 
                                               + 'strength=' + this.args[3] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Random bytes: ' + Memory.readUtf8String(this.args[1])) + ' Len: ' + this.args[2]);
                        console.log(utils.colors.green('Security strength: ' + this.args[3]));

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();

    // RAND_priv_bytes
    (function() {
        var name = 'RAND_priv_bytes';
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

                        // int RAND_priv_bytes(unsigned char *buf, int num);

                        this.args = [];
                        this.args.push(args[0]);
                        this.args.push(args[1]);
                    },

                    onLeave: function(result) {
                        console.log(name + '(' + 'buf=' + this.args[0] + ', '  
                                               + 'num=' + this.args[1] + ') = ' 
                                               + result);
                        
                        console.log(utils.colors.green('Random bytes: ' + Memory.readUtf8String(this.args[0])) + ' Len: ' + this.args[1]);

                        if (global.debug_btrace == true) {
                            console.log(utils.colors.red(utils.backtrace(this.context)));
                        }
                    },
                });
            }
            catch (error) {
                console.error(error);
            }
        }
    }
    )();
}

function hex(arrayBuffer)
{
    return Array.from(new Uint8Array(arrayBuffer))
        .map(n => n.toString(16).padStart(2, "0"))
        .join("");
};



hooks();