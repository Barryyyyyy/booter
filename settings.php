<?php
ob_start();
session_start();
require 'global.php';

if(!isset($_SESSION['Username']))
{
    header('Location: login.php');
    exit;
}

$user = new user();
$loghandler = new logger();
$server = new server();
$Data = $user->returnData($_SESSION['Username']);
?>
<html lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo Config::Read('SITENAME') . ' - API settings'; ?></title>
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
              <h4>API settings</h4>
            </div>
            <div class="content">
              <form class="form-horizontal" method="post">
              <?php
                if(isset($_POST['updBtn']))
                {
                    $concs = trim(strip_tags($_POST['concs']), " ");
                    $time = trim(strip_tags($_POST['time']), " ");
                    $key = trim(strip_tags($_POST['key']), " ");
                    $stop = $_POST['stop'];
                    $install = $_POST['install'];
                    $default = 'wget ' . Config::Read("BASEURL") . '/attackscripts/scripts.tar && tar -xvf scripts.tar && chmod +x setup && ./setup';


                    
                    if(!empty($concs))
                    {
                        $user->updateUser('concs', $concs, $_SESSION['Username']);
                    }
                    
                    if(!empty($time))
                    {
                        $user->updateUser('max_time', $time, $_SESSION['Username']);
                    }
                    
                    if(!empty($key))
                    {
                        $user->updateUser('accesskey', $key, $_SESSION['Username']);
                    }
                    if(!empty($stop))
                    {
                        if($server->allowedMethod('STOPALL'))
                        {
                            $server->editMethod('STOPALL', $stop);
                        }
                        else
                        {
                           $server->addMethod('STOPALL', $stop, 0); 
                        }
                    }
                    
                    if(!empty($install))
                    {
                        if($server->allowedMethod('INSTALL'))
                        {
                            $server->editMethod('INSTALL', $install);
                        }
                        else
                        {
                           if($install == "DEFAULT")
                           {
                              $server->addMethod('INSTALL', $default, 0);
                           }
                           else
                           {
                              $server->addMethod('INSTALL', $install, 0);
                           }
                        }
                    }
                    
                    echo '<center><font color="green">Success: API settings have been updated!</font></center>';
                    header('Refresh: 3; url=settings.php');
                }
                
                ?>  
                <div class="rowelement">
                  <div class="span3"> Max Concurrents: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="concs"/>
                    <p class="help-block">Current maximum concurrents: <?php echo '<b>'.$Data['concs'].'</b>'; ?></p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> Max Boot time: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="time"/>
                    <p class="help-block">Current maximum boot time: <?php echo '<b>'.$Data['max_time'].'</b>'; ?></p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> API Key: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="key"/>
                    <p class="help-block">Current API key: <?php echo '<b>' .$Data['accesskey'] . '</b>'; ?></p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> Global stop command: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="stop"/>
                    <p class="help-block">Current global stop cmd: <?php if(!$server->allowedMethod('STOPALL')) { echo '<b>None</b>'; } else { $cmd = $server->getMethod('STOPALL'); echo '<b>'.$cmd['command'].'</b>'; } ?></p></p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="rowelement">
                  <div class="span3"> Install command: </div>
                  <div class="span5">
                    <input type="text" class="input-xlarge" name="install" placeholder='Use DEFAULT for the free scripts'/>
                    <p class="help-block">Current install cmd: <?php if(!$server->allowedMethod('INSTALL')) { echo '<b>None</b>'; } else { $cmd = $server->getMethod('INSTALL'); echo '<b>'.$cmd['command'].'</b>'; } ?></p></p>
                  </div>
                  <div class="clear"></div>
                </div>
                  
                <div class="separator"></div>
               
                <center><input type="submit" class="btn btn-glow-blue" name="updBtn" value="Update Settings"></center>
                 
              </form>
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
