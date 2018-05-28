# php-csrf
Single PHP library file for protection over Cross-Site Request Forgery

## Example usage

```php
<?php
    // Load library
    include('php-csrf.php');
    // Init list of hashes
    $csrf = new CSRF();
?>
<form>
    <?php
        // Generate token and print it's html input
        echo $csrf->input('contact-form');
    ?>
    ...
</form>
```

```php
<?php
    // Load library
    include('php-csrf.php');
    // Init list of hashes
    $csrf = new CSRF();

    // After form submit
    // Validate that a correct token was given
    if ($csrf->validate('contact-form')) {
        // Success
    }
    else {
        // Failure
    }
```
