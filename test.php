<?php

include(__DIR__ . '/PersonalEncrypt.php');

$number = 1;
$salt = "some secret salt";

if ($argc > 2) {
    $number = intval($argv[1]);
    $salt = strval($argv[2]);
}

$encrypted = PersonalEncrypt::encrypt($number, $salt);
$decrypted = PersonalEncrypt::decrypt($encrypted, $salt);

echo "Original  ... " . $number . PHP_EOL;
echo "Encrypted ... " . $encrypted . PHP_EOL;
echo "Decrypted ... " . $decrypted . PHP_EOL;
echo "Status    ... " . ($decrypted == $number ? 'SUCCESS' : 'ERROR') . PHP_EOL;

