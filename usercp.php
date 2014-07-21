<?php
ob_start();
session_start();
require 'global.php';

$server = new server();
$user = new user();

if(!isset($_SESSION['Username']))
{
    header('Location: login.php');
    exit;
}
?>
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo Config::Read('SITENAME') . ' - User CP'; ?></title>
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
<!--[if lt IE 9]><link href="application/libs/frontend/css/ie-hacks.css" rel="stylesheet" media="screen"><![endif]-->
</head>
<body>
<div class="navbar navbar-fixed-top">
  <div class="navbar-inner">
    <div class="container">
      <div id="header">
        <div id="info">
          <ul id="userBox">
              <li class="dropdown"><a class="dropdown-toggle" data-toggle="dropdown" href=""><?php echo htmlspecialchars($_SESSION['Username']); ?> <b class="caret"></b></a>
              <ul class="dropdown-menu">
                <li><a href="usercp.php"><span class="icon-acc"></span> Account Settings</a></li>
                <li class="divider"></li>
                <li><a href="logout.php"><span class="icon-off"></span><strong>Logout</strong></a></li>
              </ul>
            </li>
          </ul>
        </div>
        <div class="clear"></div>
      </div>
    </div>
  </div>
</div>
<div id="main">
  <div class="container bg">
    <div class="row">
      <div class="span3">
        <div class="sidebar">
          <ul class="side-nav sliding_menu collapsible">
            <li><a class="current" href="index.php"><span class="icon_dash"></span>Dashboard</a></li>
            <li><a href=""><span class="icon_cont"></span>Control Panel</a>
              <ul class="acitem">
                <li><a href="logs.php"><span class="sidenav-icon"><span class="sidenav-link-color"></span></span>Attack Logs</a></li>
                <li><a href="settings.php"><span class="sidenav-icon"><span class="sidenav-link-color"></span></span>API Config</a></li>
                <li><a href="servers.php"><span class="sidenav-icon"><span class="sidenav-link-color"></span></span>Server Management</a></li>
                <li><a href="methods.php"><span class="sidenav-icon"><span class="sidenav-link-color"></span></span>Method Management</a></li>
              </ul>
            </li>
            <li><a href=""><span class="icon_stats"></span>Statistics</a>
              <ul class="acitem">
                  <li><center>Current Running attacks: <b><?php echo $user->attacksRunning($_SESSION['Username']); ?></b></center></li>
              <li><center>Number of online servers: <b><?php echo count($server->getServers()); ?></b></center></li>
              <li><center>Custom methods created: <b><?php echo count($server->getMethods()); ?></b></center></li>
              </ul>
            </li>
          </ul>
        </div>
      </div>
      <div class="span9">
        <div class="pagetitle">
          <h2>Change your account details</h2>
        </div>
          <div class="box">
            <div class="header">
              <h4>Change your email</h4>
            </div>
            <div class="content">
              <form class="form-horizontal" method="post">
              <?php
                if(isset($_POST['updBtn']))
                {
                    $old = trim(strip_tags($_POST['old']), " ");
                    $new = trim(strip_tags($_POST['new']), " ");
                    $data = $user->returnData($_SESSION['Username']);
                    
                    if(empty($old) || empty($new))
                    {
                        echo '<center><font color="red">Error: Please fill in all fields</font></center>';
                    }
                    elseif(!filter_var($old, FILTER_VALIDATE_EMAIL) || !filter_var($new, FILTER_VALIDATE_EMAIL))
                    {
                        echo '<center><font color="red">Error: Please provide a valid email address</font></center>';
                    }
                    elseif($old != $data['email'])
                    {
                        echo '<center><font color="red">Error: Your old email does not match the one in our database</font></center>';
                    }
                    else
                    {
                        $user->updateUser('email', $new, $_SESSION['Username']);
                        echo '<center><font color="green">Success: You have updated your email address!</font></center>';
                        header('Refresh: 3; url=usercp.php');
                    }
                }
              ?>
                <div class="rowelement">
                  <div class="span3"> Old email: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="old"/>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> New email: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="new"/>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="separator"></div>
               
                <center><input type="submit" class="btn btn-glow-blue" name="updBtn" value="Update Email"></center>
                 
              </form>
            </div>
          </div>
          
          <div class="box">
            <div class="header">
              <h4>Change your password</h4>
            </div>
            <div class="content">
              <form class="form-horizontal" method="post">
              <?php
                if(isset($_POST['updBtn']))
                {
                    $newpass = trim(strip_tags($_POST['newpass']), " ");
                    $repeat = trim(strip_tags($_POST['repeat']), " ");
                    
                    if(empty($newpass) || empty($repeat))
                    {
                        echo '<center><font color="red">Error: Please fill in all fields</font></center>';
                    }
                    elseif($newpass != $repeat)
                    {
                        echo '<center><font color="red">Error: The passwords you provided do not match!</font></center>';
                    }
                    else
                    {
                        $hashed = $user->hashPassword($newpass);
                        $user->updateUser('password', $hashed, $_SESSION['Username']);
                        echo '<center><font color="green">Success: You have updated your password!</font></center>';
                        header('Refresh: 3; url=usercp.php');
                    }
                }
              ?>
                <div class="rowelement">
                  <div class="span3"> New password: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="newpass"/>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> Repeat password: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="repeat"/>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="separator"></div>
               
                <center><input type="submit" class="btn btn-glow-blue" name="updBtn2" value="Update Password"></center>
                 
              </form>
            </div>
          
          <div class="clear"></div>
        </div>
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
