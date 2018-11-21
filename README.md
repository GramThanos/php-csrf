![latest release](https://img.shields.io/badge/Version-1.0.1-green.svg?style=flat-square)
![latest release](https://img.shields.io/badge/PHP->=5.3.0-blue.svg?style=flat-square)

# PHP-CSRF
### Cross-Site Request Forgery protection PHP library

PHP-CSRF manage, produce and validate hashes on the user's session to provide a basic protection from cross-site request forgery.


___


## Example usage

```php
<?php
    // Include the PHP-CSRF library
    include('php-csrf.php');
    // Start or Resume a session
    session_start();
    // Initialize an instance
    $csrf = new CSRF();

    // If form was submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Validate that a correct token was given
        if ($csrf->validate('my-form')) {
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
    <?=$csrf->input('my-form');?>
    ...
    <input type="submit" value="Submit"/>
</form>
```


___


## API


Create a csrf object
 - `$csrf = new CSRF($session_name='csrf-lib', $input_name='key-awesome', $hashTime2Live=0, $hashSize=64);`
    - `$session_name` the name to be used for the session variable.
    - `$input_name` the name to be used on the HTML input with the hash.
    - `$hashTime2Live` the default hash live time of each hash in seconds. Should be `>=0`. If zero, by default the hash will not expire.
    - `$hashSize` the default hash size in chars. Should be `>0`.


Clear excess hashes
 - `$deleted = $csrf->clearHashes($context='', $max_hashes=0);`
    - `$context` the name of the group to clear
    - `$max_hashes` the number of hashes to keep. If the hash population is bigger, the oldest hashes will be deleted.
    - returns the number of deleted hashes.


Generate HTML input code
 - `echo $csrf->input($context='', $time2Live=-1, $max_hashes=5)`
    - `$context` the name of the group to save the hash to. Usually, it is different for each form.
    - `$time2Live` the hash live time in seconds. If zero, the hash will not expire. If negative, the default value will be used.
    - `$max_hashes` the hash limit of the group. If the group has already reached this limit, the oldest hash will be discarded.
    - returns a string with the HTML code. Example return value `'<input type="hidden" name="key-awesome" value="1234567890ABCDEF1234567890ABCDEF"/>'`.


Check if a valid hash was posted
 - `$is_valid = $csrf->validate($context='', $hash=null)`
    - `$context` the name of the group to search for the hash into.
    - `$hash` the hash to validate. If `null`, the hash will be retrieved by the `$_POST` or the `$_GET` objects.
    - returns `true` if the validation was successful or `false` otherwise.


The hashes are saved on the `$_SESSION` under the a single variable using `serialize` and `unserialize`. Thus, if the session expires or get destroyed, the hashes would too.


___


## About the Security

This library uses the [openssl_random_pseudo_bytes](http://php.net/manual/en/function.openssl-random-pseudo-bytes.php) function to generate random hashes.
In order to be sure that your system produce produce cryptographically strong hashes, you should run the following PHP code and check the result.

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

This library was created to provide a basic protection from cross-site request forgery. Thus, sophisticated attacks like a timing attack may break the protection.

By using relative big hash sizes, relative short hash expiration times and small group hash limits, you can strengthen the security.


___


### License

This project is under [The MIT license](https://opensource.org/licenses/MIT).
I do although appreciate attribute.

Copyright (c) 2018 Grammatopoulos Athanasios-Vasileios

___

[![GramThanos](https://avatars2.githubusercontent.com/u/14858959?s=42&v=4)](https://github.com/GramThanos)
[![DinoDevs](https://avatars1.githubusercontent.com/u/17518066?s=42&v=4)](https://github.com/DinoDevs)
