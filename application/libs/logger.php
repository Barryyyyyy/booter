<?php

class logger
{
    public function getLogs()
    {
        try
        {
           $conn = database::getConnection();
           $stmt = $conn->prepare('SELECT * FROM logs ORDER BY id DESC');
           $stmt->execute();
           $result = $stmt->fetchAll();
           
           return $result;
        } 
        catch (PDOException $error) 
        {
            return $error->getMessage();
        }
    }
    
    public function insertLog($customer, $target_ip, $target_port, $time, $method)
    {
        $start = time();
        $end = $start + $time;
        $date = date('d-m-Y H:i:s');
        $status = 'active';
        
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare('INSERT INTO logs (`username`, `target_ip`, `target_port`, `attack_time`, `attack_method`, `time_start`, `time_end`, `status`, `date`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
            $stmt->execute(array($customer, $target_ip, $target_port, $time, $method, $start, $end, $status, $date));        
        } 
        catch (PDOException $error) 
        {
            return $error->getMessage();
        }
    }
    
    public static function updateLogs()
    {
	try
	{
            $time = time();
            $init = database::getConnection();
            $stmt = $init->prepare('UPDATE `logs` SET status = "in-active" WHERE ? > `time_end`');
            $stmt->execute(array($time));	
	}
	catch(PDOException $error)
	{
            return $error->getMessage();
	}                
    }
}
?>

