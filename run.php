<?php

use Wumvi\Utils\Sign;

include './vendor/autoload.php';

$salt = '123';
//$sign = Sign::makeSign('1:3', $salt);
//var_dump(Sign::checkSession($sign . ':1:3', $salt));
echo Sign::makeSign('test', '123');
exit;
$data = '1423:33422';
$data = json_encode(['test' => 1]);
$rawData = Sign::makeSignData($data, $salt);
echo $rawData, PHP_EOL;
echo Sign::getSignData($rawData, $salt), PHP_EOL;
