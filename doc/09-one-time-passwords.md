One time passwords (OTP) is a password that is valid for only one login session or transaction. It can be used for multi-factor authentication or lost password recovery. phpSec provides a class for creating and validating passwords, but the delivery method must be implemented separately.
phpsecOtp has two main methods, phpsecOtp::generate() and phpsecOtp::validate().

### Generating a OTP ###
You should only generate a OTP when you require the user to supply one. The phpsecOtp::generate() takes several parameters that allows you to specify what the OTP will be used for. This way you ensure that the OTP is only used for the intended action.

    <?php
    $action = 'login';
    $data['user'] = $_POST['username'];
    
    $otp = phpsecOtp::generate($action, $data);

The *$action* string specifies the action that the OTP will be used for. This is required. The *$data* array allows you to specify additional data about the request, making sure the OTP is used with the correct parameters.
This is an optional setting.

The next step is to deliver the OTP to the user, using a trusted channel. For example an encrypted e-mail, SMS or a pidgin. For now phpSec does not contain any methods for doing this.

### Validating a OTP ####
When validating a OTP all you need is a simple call to the phpsecOtp::validate() method.

    <?php
    $action = 'login';
    $data['user'] = $_POST['username'];
    
    if(phpsecOtp::validate($_POST['otp'], $action, $data)) {
      // Success. Do the rest of the login stuff here.  
    } else {
      echo 'Login failed.';
    }

The *$action* and *$data* parameters must be identical to the one used when creating the OTP or else the validation will fail.

