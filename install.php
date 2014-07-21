<?php
ob_start();
require 'global.php';
require ROOT . 'application/libs/installer.php';
?>

<!DOCTYPE HTML>
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Installer</title>
<link href="application/libs/frontend/css/bootstrap.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/bootstrap-responsive.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/bootstrap-formhelpers.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/style.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/prettify.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/smoothness/jquery-ui-1.8.16.custom.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/datatable/datatable_custom.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/fullcalendar.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/elfinder.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/flot/jquery.flot_custom.css" rel="stylesheet" media="screen">
<link href="application/libs/frontend/css/validationEngine.css" rel="Stylesheet" media="screen">
<link href="application/libs/frontend/js/jQuery-UI-FileInput/css/enhanced.css" rel="Stylesheet" media="screen">
<link href="application/libs/frontend/css/fancybox/jquery.fancybox.css" rel="stylesheet" media="screen">
<!--[if lt IE 9]><link href="css/ie-hacks.css" rel="stylesheet" media="screen"><![endif]-->
</head>
<body>
<div id="main">
  <div class="container-fluid">
    <div class="row-fluid">
      <div id="main-content" class="login-content">
        <form class="form-signin" id="validation" method="post">
            <div>
                <center>
                    <h3><?php echo Config::Read('SITENAME') . ' - Installer'; ?></h3>
                    <br>
                </center>
            </div>
            
          <p>Username:</p>
          <div class="input-prepend"><span class="add-on"><span class="icon-user"></span></span>
            <input type="text" class="span11 validate[required]" placeholder="Admin username" name="username">
          </div>
          
          <p>Email:</p>
          <div class="input-prepend"><span class="add-on"><span class="icon-lock"></span></span>
            <input type="text" class="span11 validate[required]" placeholder="Admin email" name="email">
          </div>
          
          <p>Password:</p>
          <div class="input-prepend"><span class="add-on"><span class="icon-lock"></span></span>
            <input type="password" class="span11 validate[required]" placeholder="Admin password" name="password">
          </div>
          
          <p>API key:</p>
          <div class="input-prepend"><span class="add-on"><span class="icon-lock"></span></span>
            <input type="text" class="span11 validate[required]" placeholder="Ex: 8975631" name="key">
          </div>
          
          <p>Max Concurrents:</p>
          <div class="input-prepend"><span class="add-on"><span class="icon-lock"></span></span>
            <input type="text" class="span11 validate[required]" placeholder="Max concurrents" name="concs">
          </div>
          
          <p>Max Attack time:</p>
          <div class="input-prepend"><span class="add-on"><span class="icon-lock"></span></span>
            <input type="text" class="span11 validate[required]" placeholder="Max attack time" name="time">
          </div>
           <?php
           if(isset($_POST['goBtn']))
           {
               $user = trim(strip_tags($_POST['username']), " ");
               $email = trim(strip_tags($_POST['email']), " ");
               $pass = trim(strip_tags($_POST['password']), " ");
               $key = trim(strip_tags($_POST['key']), " ");
               $concs = trim(strip_tags($_POST['concs']), " ");
               $time = trim(strip_tags($_POST['time']), " ");
               
               $handler = new installer();
               $handler2 = new user();

               
               if(empty($user) || empty($email) || empty($pass) || empty($key) || empty($concs) || empty($time))
               {
                   echo '<font color="red">Error: Please fill in all fields!</font>';
               }
               elseif(!ctype_alnum($user) || !ctype_alnum($pass) || !ctype_alnum($key) || !ctype_alnum($concs) || !ctype_alnum($time))
               {
                   echo '<font color="red">Error: Alpha Numeric values only!</font>';
               }
               elseif(!filter_var($email, FILTER_VALIDATE_EMAIL))
               {
                   echo '<font color="red">Error: This is not a valid email address!</font>';
               }
               else
               {
                   $ip = $_SERVER['REMOTE_ADDR'];
                   
                   $handler->createTables();
                   $handler2->register($user, $email, $pass, $ip, $time, $concs, $key);
                   
                   echo '<font color="green">Success: You have installed ' . Config::Read('SITENAME');
                   header('Refresh: 3; url=login.php');
                   unlink('install.php');
               }
           }
           ?>
          <button class="btn btn-info pull-right" type="submit" name="goBtn">Install</button>
          <div class="clear"></div>
        </form>
      </div>
    </div>
  </div>
</div>
<script type="text/javascript" src="application/libs/frontend/js/jquery.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/charts/flot/jquery.flot.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/charts/flot/jquery.flot.pie.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/charts/flot/jquery.flot.symbol.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/charts/flot/jquery.flot.axislabels.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/charts/flot/jquery.flot.resize.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/charts/jquery.sparkline.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jquery.nicescroll.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jquery.autogrowtextarea.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jquery.dataTables.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/dataTable_bootstrap.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/fullcalendar.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/elfinder.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jquery-ui-1.8.16.custom.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jquery.fancybox.pack.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jQuery-UI-FileInput/js/enhance.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jQuery-UI-FileInput/js/fileinput.jquery.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jQuery-validation/jquery.validationEngine.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jQuery-validation/languages/jquery.validationEngine-en.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/inputmask.jquery.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/uniform.jquery.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/chosen.jquery.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/bootstrap-timepicker.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jquery.tagsinput.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/jquery.cleditor.min.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/bootstrap.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/prettify.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/accordion.jquery.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/ios-orientationchange-fix.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/custom.js"></script>
<script type="text/javascript" src="application/libs/frontend/js/charts-custom.js"></script>
<!--[if lt IE 9]><script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script><![endif]-->
<!--[if lt IE 9]><script src="http://css3-mediaqueries-js.googlecode.com/svn/trunk/css3-mediaqueries.js"></script><![endif]-->
</body>
</html>