There are some advanced settings you can use to fine tune phpSec to your needs. Not all of them are mentioned here, but here are some of them.

Defining custom charset for the XSS filter:

    phpsec::$_charset = 'iso-8859-1'; // Default: utf-8
    phpsec::init();
