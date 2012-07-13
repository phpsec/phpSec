The phpSec session handler is an advanced session handler that changes the way session data is handled by the web server. The phpSec session handler has a number of advantages over the regular PHP session handler.

Changing session ID
-------------------
The same session ID is only used once. This makes session hijacking harder. The session ID is a 128 byte string, that makes it just about impossible to guess a session ID.

Safe storage
------------
All session data is encrypted using a user specific encryption key that is stored in a cookie on the users computer. This key is changed each 30 seconds. The data is saved in the phpSec store, allowing for storage in databases or flat files.

Easy to use
-----------
All you have to do to use the phpSec session handler is to add phpSec to your application as described in the getting started page. The session handler is enabled by default.
To disable just set *phpsec::$_sessenable* to *false* like this:

    require_once 'phpsec.class.php';
    phpsec::$_dsn = 'filesystem:/var/www/phpSec/data'; /* Note the filesystem: before the path. */
    
    phpsec::$_sessenable = false; /* Disable phpSec session handler. */
    
    phpsec::init();
