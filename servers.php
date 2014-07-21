<?php
ob_start();
session_start();
require 'global.php';

$server = new server();
$user = new user();
$dir = '/' . basename(__DIR__) . '/';

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
<title><?php echo Config::Read('SITENAME') . ' - Server Management'; ?></title>
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
          <h2>Modify your API here.</h2>
        </div>
          <div class="box">
            <div class="header">
              <h4>Add a server</h4>
            </div>
            <div class="content">
              <form class="form-horizontal" method="post">
                  
              <?php
              
              if(isset($_POST['updBtn']))
              {
                  $ip = trim(strip_tags($_POST['ip']), " ");
                  $username = trim(strip_tags($_POST['username']), " ");
                  $password = trim(strip_tags($_POST['password']), " ");
                  $link = trim(strip_tags($_POST['link']), " ");
                  
                  if(empty($ip) || empty($username) || empty($password))
                  {
                      echo '<center><font color="red">Error: Please fill in all fields</font></center>';
                  }
                  elseif(!filter_var($ip, FILTER_VALIDATE_IP))
                  {
                      echo '<center><font color="red">Error: This is not a valid IP address</font></center>';
                  }
                  elseif(!ctype_alnum($username) || !ctype_alnum($password))
                  {
                      echo '<center><font color="red">Error: Alpha Numeric values only please</font></center>';
                  }
                  else
                  {
                      if($server->allowedMethod('INSTALL'))
                      {
                            $server->installServer($ip, $username, $password); 
                      }
                      $server->addServer($ip, $username, $password);
                      echo '<center><font color="green">Success: You have added a server! Refreshing..</font></center>';
                      header('Refresh: 3; url=servers.php');
                  }
              }
              
              
              ?>
                <div class="rowelement">
                  <div class="span3"> Server IP: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="ip"/>
                    <p class="help-block">This is the attack server's IP address</p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> Attack Server Username: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="username"/>
                    <p class="help-block">This will be the root password for the server</p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> Attack Server Password: </div>
                  <div class="span5">
                    <input type="password" class="input-xlarge" name="password"/>
                    <p class="help-block">This will be the root password for the attack server</p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="separator"></div>
               
                <center><input type="submit" class="btn btn-glow-blue" name="updBtn" value="Add Server"></center>
                 
              </form>
            </div>
          </div>
          
          <div class="box">
            <div class="header">
              <h4>My servers</h4>
            </div>
            <div class="content">
                <table class="normal bt-dataTable" border="0" cellpadding="0" cellspacing="0" width="100%" id="dataTable">
                <thead>
                  <tr>
                    <th>Pool ID</th>
                    <th>Server IP</th>
                    <th>Server Username</th>
                    <th>Server Password</th>
                    <th>Response in m/s</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                <?php
                if(isset($_GET['delete']))
                {
                        $server->deleteServer($_GET['delete']);
                        header('Refresh: 3; url=servers.php');
                    
                }
                
                $servers = $server->getServers();
                $i = 0;
                foreach($servers as $Server)
                {
                    $id = $Server["id"];
                    echo '<tr>
                            <td><center>Pool ' . $i . '</center></td>
                            <td><center>' . $Server["ip"] . '</center></td>
                            <td><center>' . $Server["username"] . '</center></td>
                            <td><center>******</center></td>
                            <td><center>' . $server->responseTime($Server["ip"]) . '</center></td>
                            <td><center><button type="button" class="btn btn-lime"><a href="servers.php?delete='.$id.'">Delete</button></center></td>
                          </tr>';
                    $i++;
                }
                ?>  
                </tbody>
              </table>
            </div>
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
