Encrypting data in PHP can be done easy with phpSec. phpSec implements symmetric encryption using the mcrypt library, end is extremely easy to use.

### Quick example ###

    <?php
    $data = 'This is some extremely secret information.';
    /* Encrypt. */
    $encrypted = phpsecCrypt::encrypt($data, 'secret key');
    /* Decrypt. */
    $data = phpsecCrypt::decrypt($encrypted, 'secret key');


### Setting up algorithms and modes. ###
The default encryption algorithm used by phpSec is Rijndael 256 in CTR mode. This should be fine in most cases, but you can change this if you want to.
   <?php
   phpsecCrypt::$_algo = 'rijndael-256';
   phpsecCrypt::$_algo = 'ctr';


### Generating keys. ###
Generating good encryption keys is probably the most important thing you do, but it can also be a bit difficult. the supported key lengths differs between the different algorithms and encryption modes, but for Rijndael 256 in CTR mode a 32 byte key should be used.
A common mistake when generating keys it to use a key with ASCII characters only, this will give you extremely low entropy and should be avoided. 
If you want to generate a 32 byte binary key you could use phpSec:

    <?php
    $key = phpsecRand::bytes(32);

Note that a binary key often needs spacial handling when storing. Base64 encoding can often be usefull.

### Encrypting data. ###
This is the easy part. To encrypt your data just pass the data you want to encrypt and the key to phpsecCrypt::encrypt().

    <?php
    $encrypted = phpsecCrypt::encrypt($data, $key);

The data could be a string, array or even an object.
The returned data will be a JSON encoded array ready for storage. 

    {"algo":"rijndael-256","mode":"ctr","iv":"qaauGpbl9XFhZ\/fi9VSZPNrwP2JQC+q+gYL8gL92ZUw=","cdata":"ZvDdzPRhbgyLpwaq2rr+oFhxR4389N14g7\+5shFT9qK8sDVi81","mac":"vzQk4g\/cX1EQbQ7x0PFDHKJ4XSzksV+PPz4EG2rplGA="}

As you can see the encrypted data also contains the algorithm and mode used. This means that you could change preferred algorithm in your application, and still be able to decrypt old data. There is also a message authentication code to ensure data integrity,

### Decrypting data. ###
To the decrypt data all you need to do is to pass the JSON encoded array along with the same key that you used when encrypting the data to phpsecCrypt::decrypt(). phpSec will automatically know what algorithm and mode to use to decrypt the data.

    <?php
    $data = phpsecCrypt::decrypt($encrypted, $key);

