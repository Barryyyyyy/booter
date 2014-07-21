<?php
class Config 
{
	public static $config = array();

	public static function Read($key)
	{
		return self::$config[$key];
	}	

	public static function Write($key, $value)
	{
		self::$config[$key] = $value;
	}


	public static function returnConfig($config_name)
	{
		try
		{
			$dbh = DBFactory::getInstance();
			$handler = $dbh->prepare('SELECT * FROM `config` WHERE option_name = :option');
			$handler->execute(array(':option' => $config_name));
			return $handler->fetch(PDO::FETCH_ASSOC);
		}
		catch(PDOException $error)
		{
			return $error->getMessage();
		}
	}

	public static function updateConfig($config_name, $new_value)
	{
		try
		{
			$dbh = DBFactory::getInstance();
			$handler = $dbh->prepare('UPDATE `config` SET `option_value` = :value WHERE `option_name` = :option');
			$handler->execute(array(':value' => $new_value, ':option' => $config_name));
		}
		catch(PDOException $error)
		{
			return $error->getMessage();
		}
	}
}
?>

