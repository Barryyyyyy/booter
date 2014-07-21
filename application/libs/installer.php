<?php

class installer
{
    public function createTables()
    {
        try
        {
            $logs = 'CREATE TABLE IF NOT EXISTS `logs` (
            `id` int(11) NOT NULL AUTO_INCREMENT,
            `username` varchar(30) NOT NULL,
            `target_ip` varchar(30) NOT NULL,
            `target_port` varchar(30) NOT NULL,
            `attack_time` varchar(30) NOT NULL,
            `attack_method` varchar(30) NOT NULL,
            `time_start` varchar(30) NOT NULL,
            `time_end` varchar(30) NOT NULL,
            `status` varchar(30) NOT NULL,
            `date` varchar(30) NOT NULL,
            PRIMARY KEY (`id`)
            )';
        
            $methods = 'CREATE TABLE IF NOT EXISTS `methods` (
            `id` int(11) NOT NULL AUTO_INCREMENT,
            `name` varchar(50) NOT NULL,
            `classification` int(50) NOT NULL,
            `command` varchar(300) NOT NULL,
            PRIMARY KEY (`id`)
            )';
        
            $servers = 'CREATE TABLE IF NOT EXISTS `servers` (
            `id` int(11) NOT NULL AUTO_INCREMENT,
            `ip` varchar(50) NOT NULL,
            `username` varchar(50) NOT NULL,
            `password` varchar(50) NOT NULL,
            `response` varchar(50) NOT NULL,
            PRIMARY KEY (`id`)
            )';
        
            $users = 'CREATE TABLE IF NOT EXISTS `users` (
            `id` int(11) NOT NULL AUTO_INCREMENT,
            `username` varchar(50) NOT NULL,
            `email` varchar(40) NOT NULL,
            `password` varchar(100) NOT NULL,
            `ip` varchar(30) NOT NULL,
            `max_time` int(50) NOT NULL,
            `concs` int(30) NOT NULL,
            `accesskey` varchar(30) NOT NULL,
            PRIMARY KEY (`id`)
            )';
        
            $dbh = database::getConnection();
            $dbh->exec($logs);
            $dbh->exec($methods);
            $dbh->exec($servers);
            $dbh->exec($users);
        }
        catch(PDOException $error)
        {
            return $error->getMessage();
        }
    }
}
?>

