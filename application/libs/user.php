<?php
class user
{
	/*public function hashPassword($password)
        {
            $options = ['cost' => 12,];
            return password_hash($password, PASSWORD_BCRYPT, $options);
        }
    */

        public function better_crypt($input, $rounds = 7)
        {
            $salt = "";
            $salt_chars = array_merge(range('A','Z'), range('a','z'), range(0,9));
            for($i=0; $i < 22; $i++) {
                $salt .= $salt_chars[array_rand($salt_chars)];
        }
            return crypt($input, sprintf('$2a$%02d$', $rounds) . $salt);
        }

        public function hashPassword($password)
        {
            return $this->better_crypt($password);
        }
        
        public function login($username, $password)
        {
            try
            {
                $stmt = database::getConnection();
                $dbh = $stmt->prepare('SELECT * FROM users WHERE username = ?');
                $dbh->execute(array($username));
                $result = $dbh->fetch(PDO::FETCH_ASSOC);

                if(crypt($password, $result['password']) == $result['password']) 
                {
                    return true;
                }
                else
                {
                    return false;
                }
                              
            }
            catch(PDOException $error)
            {
                return $error->getMessage();
            }
        }
        
        public function register ($username, $email, $password, $ip_address, $max_time, $concs, $key)
        {
            try
            {
               $pass = $this->hashPassword($password);
               
               $conn = database::getConnection();
               $stmt = $conn->prepare('INSERT INTO users (`username`, `email`, `password`, `ip`, `max_time`, `concs`, `accesskey`) VALUES (?, ?, ?, ?, ?, ?, ?)');
               $stmt->execute(array($username, $email, $pass, $ip_address, $max_time, $concs, $key));
               
            } 
            catch (PDOException $error)
            {
                return $error->getMessage();
            }
        }
        
        public function updateUser($row, $value, $user)
        {
            try
            {
                $conn = database::getConnection();
                $stmt = $conn->prepare("UPDATE users SET $row = ? WHERE username = ?");
                $stmt->execute(array($value, $user));
            } 
            catch (PDOException $error) 
            {
                return $error->getMessage();
            }
        }
        
        public function returnData($username)
        {
            try
            {
               $conn = database::getConnection();
               $stmt = $conn->prepare('SELECT * FROM users WHERE username = ?');
               $stmt->execute(array($username));
               $result = $stmt->fetch(PDO::FETCH_ASSOC);
               
               return $result;
            }
            catch(PDOException $error)
            {
                return $error->getMessage();
            }
        }
        
        public function isBanned($username)
        {
            $data = $this->returnData($username);
            
            if($data['rank'] == 'banned')
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        
        public function freeSlot($customer)
        {
            $data = $this->returnData($customer);
            $max_concs = $data['concs'];
            $attacks = $this->attacksRunning($customer);
            
            if(count($attacks) >= $max_concs)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        
        public function attacksRunning($customer)
        {
            try
            {
                $conn = database::getConnection();
                $stmt = $conn->prepare('SELECT * FROM logs WHERE username = ? AND active = ?');
                $stmt->execute(array($customer, 'true'));
                $result = $stmt->fetchAll();
                
                return count($result);
            } 
            catch (PDOException $error) 
            {
                return $error->getMessage();
            }
        }
        
}
?>