*Note: This method requires phpSec 0.3-beta. For older versions see [phpSec::pw](https://phpseclib.com/manual/pw).*

Safe storage of your users password is an important step to increase the security of your web-application. phpSec implements [bcrypt](http://en.wikipedia.org/wiki/Bcrypt), [sha2](http://en.wikipedia.org/wiki/SHA-2) and [pbkdf2](http://en.wikipedia.org/wiki/PBKDF2) to protect your users passwords from rainbow tables and brute force attacks in case they are compromised. You can read more about this [here](http://codahale.com/how-to-safely-store-a-password/).

phpSec creates salted hashes using the very well prooven [crypt()](http://en.wikipedia.org/wiki/Crypt_(Unix)) function. The crypt() function is available on virtually any platform. This means that a password hashed with phpSec could be validated on almost any system without any effort at all.

*Note: There is one exception. The [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) implementation in phpSec is only supported in phpSec. If you need portability use [phpsecHash](https://phpseclib.com/api/phpsec/phpsec--phpsec.hash.php/class/phpsecHash//api/phpsec/phpsec--phpsec.hash.php/class/phpsecHash/) with [bcrypt](http://en.wikipedia.org/wiki/Bcrypt).*

Creating hashes
---------------

To create a salted hash we use the [phpsecHash:create()](/api/phpsec/phpsec--phpsec.hash.php/function/phpsecHash%3A%3Acreate) method. It takes just one argument and that is the password you wish to create an hash from.

    <?php
    require_once 'phpsec.class.php';
    phpsec::init();
    
    $hash = phpsecHash::create('password');
    echo $hash;

The above code will output something like: *$pbkdf2$c=8192&dk=128&f=sha256$cSgQjF7RNrc0c(...)3ZHdrug0kd/ttLCbiH8fh4sucFK+GEI9ITYBXvNt3oYepK0MXxzjGxhcUg4UxE1yA1pRhuIhZ2KamDduyz+A==*

This value can then be stored in a database for validation at a later time.

Validating passwords
--------------------

When validating password we use the [phpsecHash::check()](/api/phpsec/phpsec--phpsec.hash.php/function/phpsecHash%3A%3Acheck) method. This method takes two arguments. The first is the password we want to check, and the second is the hash we created before. phpsecHash::check() will atomatically detect the method used to create the hash.

    <?php
    require_once 'phpsec.class.php';
    phpsec::init();
    
    if(phpsecHash::check($_POST['password'], $hash)) {
      echo "Valid password";
    }

Changing hash method
--------------------

phpSec enables you to change hashing method without making old hashes unusable. So if you started using PBKDF2 and later decides to use bcrypt, you can just tell phpSec to use bcrypt when creating new hashes. Since phpSec automatically detects the hash type when callingphpsecHash::check(), the old PBKDF2 hashes would still work.

If you want to create a hash using bcrypt all you need to do is to set *phpsecHash::$_method* to *phpsecHash::BCRYPT*.

    <?php
    require_once 'phpsec.class.php';
    phpsec::init();
    phpsecHash::$_method = phpsecHash::BCRYPT;
    
    $hash = phpsecHash::make('password');
    echo $hash;

This will produce a hash that looks like this *$2a$12$1r4Sv3VuunDtN9sbjWSgfOO6wfM9vnwE9U4fZGhBaJVVgwtz3IsI6*.

Advanced settings
------------------
There are several options you could use to tune phpsecHash to work the way you want it to work. You can find a complete list [here](/api/phpsec/phpsec--phpsec.hash.php/class/phpsecHash/).
Please note that as shown in the example above you need to set *phpsecHash::$_method* to either:

* phpsecHash::BCRYPT
* phpsecHash::PBKDF2
* phpsecHash::SHA256<
* phpsecHash::SHA512

