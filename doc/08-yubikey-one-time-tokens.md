[YubiKey](http://www.yubico.com/yubikey) is the leading one time password token for simple, open online identity protection, and with the help of phpSec your users can be using their Yubikey for authentication in your application.

### Getting ready ###
In order to use the Yubikey API you need a API key. You can [create one here](https://upgrade.yubico.com/getapikey/) for free (Yubikey required).
Then after recieving your key, you need to tell phpSec about it. Below is an exaple, you need to change this to your own client ID and secret.

    <?php
    phpsecYubikey::$_clientId     = 5118;
    phpsecYubikey::$_clientSecret = 'n7cIJF1IaL8WeTUsluWRSpRLOqs=';

### Now what? ###
To enable your users to use their Yubikey to log in, you will have to store their Yubikey ID in the user database. All Yubikey OTP contains starts with the Yubikey ID (the first characters of the passwords). This ID will be the same every time, and unique for each Yubikey. We can use this to know who the Yubikey that was used belongs to. The Yubikey ID can be extracted from a OTP with the phpsecYubikey::getYubikeyId() method. This has to be done upon registration, or later if a user want's to attach a Yubikey to his account.

    <?php
    $yubikeyId = phpsecYubikey::getYubikeyId($_POST['otp']);

We can then store *$yubikeyId* in our database as the users Yubikey ID.

### Validating a Yubikey OTP ###
When a user tries to log in using his username and Yubikey what we first do is to fetch the Yubikey that belongs to the user trying to log in. Let's say the ID from the databse is stored in *$user['yubikey']*.
Then we need to compare this to the Yubikey ID from the OTP from the login form, to make sure the Yubikey used is the same that the user has attached to his account.

    <?php
    if(phpsecYubikey::getYubikeyId($_POST['otp']) == $user['yubikey']) {
      // Yubikey belongs to user.
    } else {
      // Login failed.
    }

This is by itself not enough, becuse we still need to validate the Yubikey against the Yubico authentication servers to make sure the OTP is valid, and not beeing reused. This is done with the phpsecYubikey::verify() method. All we need to do is to expand the code from the example above.

    <?php
    if(phpsecYubikey::getYubikeyId($_POST['otp']) == $user['yubikey'] && phpsecYubikey::verify($_POST['otp'])) {
      // Yubikey belongs to user, and is valid.
    } else {
      // Login failed.
    }

### What if something goes wrong? ###
Let's face it. Something is bound to go wrong. To see the last error produced by phpsecYubikey, we can use the *phpsecYubikey::$lastError* property. Let's expand the example above one more time.
Please note that only calls to phpsecYubikey::verify() will produce errors.

    <?php
    if(phpsecYubikey::getYubikeyId($_POST['otp']) == $user['yubikey'] && phpsecYubikey::verify($_POST['otp'])) {
      // Yubikey belongs to user, and is valid.
    } else {
      // Login failed.
      echo phpsecYubikey::$lastError;
    }

### Error Codes ###

 *  YUBIKEY_CLIENT_DATA_NEEDED
    You need to specify Client ID and Client secret as described here.
 *  YUBIKEY_INVALID_OTP
    Invalid OTP passed to phpsecYubikey::verify().
 *  YUBIKEY_SERVER_ERROR
    Not able to reach Yubico authentication servers.
 *  YUBIKEY_SERVER_REPLAYED_OTP
    Server says: The OTP has already been seen by the service.
 *  YUBIKEY_SERVER_REPLAYED_REQUEST
    Server says: Server has seen the OTP/Nonce combination before.
 *  YUBIKEY_SERVER_BAD_OTP
    Server says: The OTP is invalid format.
 *  YUBIKEY_SERVER_NO_SUCH_CLIENT
    Server says: The request id does not exist.
 *  YUBIKEY_SERVER_SAYS_NO
    Some other error was returned by the server.
 *  YUBIKEY_NO_MATCH
    The key validated by the server was not the same as requested by the client.
 *  YUBIKEY_SERVER_BAD_SIGNATURE
    The HMAC signature supplied from client failed verification on the server.
 *  YUBIKEY_BAD_SERVER_SIGNATURE
    The HMAC signature supplied from the server failed verification on the client.
