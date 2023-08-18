![latest release](https://img.shields.io/badge/Version-1.0.4-green.svg?style=flat-square)
![latest release](https://img.shields.io/badge/PHP->=5.6.0-blue.svg?style=flat-square)
![latest release](https://img.shields.io/badge/License-MIT-lightgrey.svg?style=flat-square)

# PHP-CSRF
### Cross-Site Request Forgery protection PHP library

PHP-CSRF manage, generate and validate hashes, on the user's session, to provide a basic protection from Cross-Site Request Forgery.


___


## Download
 - Direct download [php-csrf.php](https://raw.githubusercontent.com/GramThanos/php-csrf/master/php-csrf.php) file (right click save as).
 - Using wget `wget -O php-csrf.php https://raw.githubusercontent.com/GramThanos/php-csrf/master/php-csrf.php`

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


Generate HTML input element code
 - `echo $csrf->input($context='', $time2Live=-1, $max_hashes=5)`
    - `$context` the name of the group to save the hash to. Usually, it is different for each form.
    - `$time2Live` the hash live time in seconds. If zero, the hash will not expire. If negative, the default value will be used.
    - `$max_hashes` the hash limit of the group. If the group has already reached this limit, the oldest hash will be discarded.
    - returns a string with the HTML code. Example return value `'<input type="hidden" name="key-awesome" value="1234567890ABCDEF1234567890ABCDEF"/>'`.

Generate javascript script element code (alternative)
 - `echo $csrf->script($context='', $name='', $declaration='var', $time2Live=-1, $max_hashes=5)`
    - `$context` the name of the group to save the hash to. Usually, it is different for each form.
    - `$name` the name of the javascript variable. If it is empty string, the name of the `input_name` will be used, but the default one is an invalid variable name.
    - `$declaration` the declaration key word of the variable, usually `var`, `let` or `const`.
    - `$time2Live` the hash live time in seconds. If zero, the hash will not expire. If negative, the default value will be used.
    - `$max_hashes` the hash limit of the group. If the group has already reached this limit, the oldest hash will be discarded.
    - returns a string with the HTML script code. Example return value `'<script type="text/javascript">var name = "1234567890ABCDEF1234567890ABCDEF";</script>'`.

Generate javascript variable code (alternative)
 - `echo $csrf->javascript($context='', $name='', $declaration='var', $time2Live=-1, $max_hashes=5)`
    - `$context` the name of the group to save the hash to. Usually, it is different for each form.
    - `$name` the name of the javascript variable. If it is empty string, the name of the `input_name` will be used, but the default one is an invalid variable name.
    - `$declaration` the declaration key word of the variable, usually `var`, `let` or `const`.
    - `$time2Live` the hash live time in seconds. If zero, the hash will not expire. If negative, the default value will be used.
    - `$max_hashes` the hash limit of the group. If the group has already reached this limit, the oldest hash will be discarded.
    - returns a string with the javascript code. Example return value `'var name = "1234567890ABCDEF1234567890ABCDEF";'`.

Generate hash as a string (alternative)
 - `echo $csrf->string($context='', $time2Live=-1, $max_hashes=5)`
    - `$context` the name of the group to save the hash to. Usually, it is different for each form.
    - `$time2Live` the hash live time in seconds. If zero, the hash will not expire. If negative, the default value will be used.
    - `$max_hashes` the hash limit of the group. If the group has already reached this limit, the oldest hash will be discarded.
    - returns a string with the hash. Example return value `'1234567890ABCDEF1234567890ABCDEF'`.


Check if a valid hash was posted
 - `$is_valid = $csrf->validate($context='', $hash=null)`
    - `$context` the name of the group to search for the hash into.
    - `$hash` the hash to validate. If `null`, the hash will be retrieved by the `$_POST` or the `$_GET` objects.
    - returns `true` if the validation was successful or `false` otherwise.


Get the hashes of a context
 - `$is_valid = $csrf->getHashes($context='', $max_hashes=-1)`
    - `$context` the name of the group to get its hashes.
    - `$max_hashes` max number of hashes to get. If negative value, all the hashes will be returned.
    - returns an array of string hashes.


The hashes are saved on the `$_SESSION` under the a single variable using `serialize` and `unserialize`. Thus, if the session expires or get destroyed, the hashes would too.


___


## About the Security

This library uses the [openssl_random_pseudo_bytes](http://php.net/manual/en/function.openssl-random-pseudo-bytes.php) function to generate random hashes.
In order to be sure that your system can produce cryptographically strong hashes, you should run the following PHP code and check the result.

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

This library was created to provide a basic protection from Cross-Site Request Forgery attacks. Thus, sophisticated attacks like a timing attack may break the protection.

By using relative big hash sizes, relative short hash expiration times and small group hash limits, you can strengthen the security.


___

### Compatibility
Compatible with PHP 5 >= 5.6.0, PHP 7, PHP 8

- [hash_equals](https://www.php.net/manual/en/function.hash-equals.php) (PHP 5 >= 5.6.0, PHP 7, PHP 8)
- [openssl_random_pseudo_bytes](https://www.php.net/manual/en/function.openssl-random-pseudo-bytes) (PHP 5 >= 5.3.0, PHP 7, PHP 8)
- [json_encode](https://www.php.net/manual/en/function.json-encode) (PHP 5 >= 5.2.0, PHP 7, PHP 8, PECL json >= 1.2.0)

___


### License

This project is under [The MIT license](https://opensource.org/licenses/MIT).
I do although appreciate attribute.

Copyright (c) 2023 Grammatopoulos Athanasios Vasileios

___

[![GramThanos](https://avatars2.githubusercontent.com/u/14858959?s=42&v=4)](https://github.com/GramThanos)
[![DinoDevs](https://avatars1.githubusercontent.com/u/17518066?s=42&v=4)](https://github.com/DinoDevs)
