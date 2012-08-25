Random isn't always random enough. The built in <a href="http://php.net/manual/en/function.mt-rand.php">random functions in PHP</a> may be good enough for displaying a random quote, or a random image. But when it comes to generating random data for use in encryption keys or other security related things the pseudo random generator provided by phpSec is preferable.

phpSec provides you with a number of different methods of collecting random data. All of them uses the same pseudo random generator, the only difference is how they return the data. All the methods are called statically from the phpsecRand class.

### Random numbers ###
Getting random numbers with phpSec is done with the phpsecRand::int() method. This method takes two arguments. The first is the lowest possible number, and the second is the highest possible number. The following example will produce a random number between 1 and 10.

    <?php
    echo phpsecRand::int(1, 10);


### Random strings ###
Random strings can be used for example to create new passwords to users in case they have lost the current password.
Random strings are created with the phpsecRand::str() method. This method takes only one argument, the length of the string to be generated. The following example will produce a random string of 10 characters.

    <?php
    echo phpsecRand::str(10);

It is also possible to define what characters to use when generating the string.

    <?php
    phpsecRand::$_charset = 'abcdef';
    echo phpsecRand::str(10);


### Random array keys ###
phpSec can also select random keys from an array. This is done with the phpsecRand::arrayRand() method. This method takes two arguments, the first one is the array to pick random keys from, and the second is the number of keys to pick. If only one key is picked this method returns a string. If multiple keys are picked it will return an array.

    <?php
    phpsecRand::$_charset = 'abcdef';
    $array = array(
      'key' => 'foo',
      'bar'
    );

    print_r(phpsecRand::arrayRand($array, 1));


### Random data ###
It is also possible to collect random bytes from phpSec. This can be used if you don't need data that is printable. A good example is if you need an encryption key. Binary data is collected using <a href="/api/phpsec/phpsec--phpsec.rand.php/function/phpsecRand%3A%3Abytes">phpsecRand::bytes()</a>. This method only takes one argument, how many bytes to produce.

    <?php
    echo phpsecRand::bytes(32);

