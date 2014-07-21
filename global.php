<?php
/* Defines */
define('DS', DIRECTORY_SEPARATOR);
define('ROOT', realpath(__DIR__) . DS);

/* Includes */
include(ROOT . 'config.php');
include(ROOT . 'application/libs' . DS . 'database.php');
include(ROOT . 'application/libs' . DS . 'server.php');
include(ROOT . 'application/libs' . DS . 'user.php');
include(ROOT . 'application/libs' . DS . 'logger.php');
include(ROOT . 'application/libs' . DS . 'network' . DS . 'SSH2.php');
include(ROOT . 'application/libs' . DS . 'network' . DS . 'SFTP.php');

/* Update ze sexy logs */
logger::updateLogs();

/* Update Server Response Time */
$var = new server();
$var->updateServers();

/* Version Detection */
if(version_compare(phpversion(), '5.4.0', '<'))
{
    die("Please upgrade to PHP 5.4.x, this source does not support anything below that!");
}

/* Check if Curl is enabled */
if(!in_array('curl', get_loaded_extensions()))
{
    die("Please install the Curl Library for this program to work!");
}


/* Check if fsockopen(); exists */
if(!function_exists('fsockopen'))
{
    die('Please enable fsockopen() in your php.ini file');
}

?>

