Altough phpSec is pretty plug and play there are some small steps you need to take before you are ready to harness the power of phpSec. The first thing is to include phpSec into your application. This is done something like this.

    require_once "phpsec.class.php";

Preparing the data storage if needed
------------------------------------
phpSec saves data in something called *the store*. Everything from session data to cache and one time passwords are saved there. Configuring the store is optional if you only want to use the basic functionality of phpSec. If you don't configure a store the following phpSec modules will be available:
  * phpsecCrypt
  * phpsecFilter
  * phpsecHash (and phpsecPw)
  * phpsecRand
  * phpsecYubikey

If you want full phpSec functionality you need to configure the store. This is done with the static **phpsec::$_dsn** variable. The store is defined as a string with the storage method followed by a colon (:), and the storage destination. So if you want to save your data using flat files to */var/www/phpSec/data* the following example would be correct.

    phpsec::$_dsn = "filesystem:/var/www/phpSec/data";

The target directory needs to be writeable by PHP, and should not be accessible trough your web server. Setting up phpSec to use mySQL is a bit more complex, but is [well described here](/node/7595). Be sure to come back here to complete your set-up.

Initializing phpSec
-------------------
phpSec is mostly a statically called library, but we still need to initialize some stuff. To do this we call the *phpsec::init()* method.

    phpsec::init();

What this actually does is to prepare the store, make sure that all the files we need are loaded and enables and starts the phpSec session handler. If you want to know more about the session handler, or how to disable it check out the [session handler](/manual/session) page.

Thats it!
---------
Thats it! After the following three lines you should be all set to start using phpSec on your application.

    require_once "phpsec.class.php";
    
    /* Optionally configure the store. */
    phpsec::$_dsn = "filesystem:/var/www/phpSec/data";
    
    phpsec::init();

To learn how to start protecting your application, read on.