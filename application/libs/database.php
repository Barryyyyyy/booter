<?php
class database
{
    public static function getConnection()
    {
        try
        {
            return new PDO('mysql:hostname=' . Config::Read('HOST') . ';dbname=' . Config::Read('DBNAME'), Config::Read('USER'), Config::Read('PASS'));
        } 
        catch (PDOException $error)
        {
            return $error->getMessage();
        }
    }
}
?>
