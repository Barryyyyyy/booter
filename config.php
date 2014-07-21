<?php
include(ROOT . 'application/libs' . DS . 'confighandler.php');

/* Note: Make sure to create an empty database, the installer will do the rest */
Config::Write('HOST', 'localhost');
Config::Write('USER', 'root');
Config::Write('PASS', 'Nutley22');
Config::Write('DBNAME', 'stress');

Config::Write('SITENAME', 'zk Stresser');
Config::Write('DENYMSG', 'Kindly fuck off or you will be swatted');
Config::Write('BASEURL', $_SERVER['SERVER_NAME']. '/booter'); //make sure to add your directory here, if you are in a directory!
Config::Write('MAIN_ACCOUNT', 'Mane');
?>