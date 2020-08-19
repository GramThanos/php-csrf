<?php
    // Include the PHP-CSRF library
    include(dirname(__FILE__) . '/../php-csrf.php');

    // First we need to start a session
    session_start();

    // Initialize an instance
    use PHPCSRFLib\CSRF;
    $csrf = new CSRF();

    $message = false;

    // If form was submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Validate that a correct token was given
        if ($csrf->validate('my-form')) {
            // Success
            $message = 'The message was submitted!';
        }
        else {
            // Failure
            $message = 'Error, action was prevented.';
        }
    }
?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>PHP-CSRF Example</title>
    </head>
    <body>

        <!-- Your normal HTML form -->
        <form method="POST">
            <!-- Print a hidden hash input -->
            <?=$csrf->input('my-form');?>

            <!-- My other form elements -->
            Message: <input type="text" name="message" value=""/><br>
            <input type="submit" value="Submit"/>
        </form>
        <br>
        <?php if ($message) echo $message; ?>

    </body>
</html>
