Cross Site Request Forgery (CSRF) is a attack method where the victim already has authenticated to a site, and the attacker uses this valid session to trick the user into making a request without his knowledge.

There are several ways to protect a site against CSRF but the most common is to use one-time tokens to validate that the request is not coming from a third party site, or happening without the knowledge of the user. You can read more about CSRF at Wikipedia.

To protect your application from CSRF attacks you can use phpSec to generate a one-time token that you include in a hidden field in your forms. When a user submits a form this token should be validated before the action requested by the user is performed.

phpSec has two static functions for this purpose phpSec::getToken() and phpSec::validToken().

Take the following example.

     /* Get one-time token and display form. */
    $token = phpsecToken::set('myform');
    echo "<form method='post'>";
    echo "<input type='hidden' name='token' value='". $token ."'>";
    echo "<input type='submit' name='do'>";
    echo "</form>";
    
    if(isset($_POST['do'])) {
      if(phpsecToken::validate('myform', $_GET['token'])) {
        echo "Valid token!";
        /* Do stuff with POST data. */
      } else {
        echo "Invalid token!";
      }
    }

phpsecToken::set() takes two arguments: The first is a string that identifies the form. The second is optional and is a integer that says how long the token should be valid, in seconds. Default is 3600.

phpsecToken::validate() also takes two arguments: The first is the same identifying string that you supplied to phpsecToken::set(). The second is the token supplied by the user.