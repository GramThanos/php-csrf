![latest release](https://img.shields.io/badge/Version-1.0.0-green.svg?style=flat-square)
![latest release](https://img.shields.io/badge/PHP->=5.3.0-blue.svg?style=flat-square)

# PHP-CSRF
### Cross-Site Request Forgery protection PHP library

PHP-CSRF manage, produce and validate hashes on the user's session to provide protection from cross-site request forgery.

___



## Example usage

```php
<?php
    // Include the PHP-CSRF library
    include('php-csrf.php');
    // Initialize an instance
    $csrf = new CSRF();

    // If form was submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Validate that a correct token was given
        if ($csrf->validate('my-contact-form')) {
            // Success
        }
        else {
            // Failure
        }
    }
?>

<!-- Your normal HTML form -->
<form method="POST">
    <!-- Print a hidden hash input -->
    <?=$csrf->input('my-contact-form');?>
    ...
    <input type="submit" value="Submit"/>
</form>
```



___



## Check if cryptographically strong

The PHP-CSRF library uses the [openssl_random_pseudo_bytes](http://php.net/manual/en/function.openssl-random-pseudo-bytes.php) function to generate hashes.
You can check if your system produce cryptographically strong hashes by runing the following PHP code.

```php
<?php
	// Test if random_pseudo is cryptographically strong in your system
	$hash = openssl_random_pseudo_bytes(32, $crypto_strong);
?>
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<title>PHP-CSRF Test</title>
	</head>
	<body>
		Is cryptographically strong: <?=($crypto_strong ? 'yes' : 'no');?><br>
	</body>
</html>
```


