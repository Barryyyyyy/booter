<?php
ob_start();
session_start();

require 'global.php';

$user = new user();
$server = new server();
$dir = '/' . basename(__DIR__);

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
<title><?php echo Config::Read('SITENAME') . ' - Control Panel'; ?></title>
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
          <h2>Dashboard</h2>
          <p>Welcome to your own personal API Control Panel!</p>
        </div>
        <div id="main-content">
          <div class="quick-buttons">
            <div class="row-fluid">
              <div class="span3"><a href="servers.php" class="btn btn-block"><i class="dashboard-icons archives_dashboard"></i><span class="dasboard-icons-title">My Servers</span></a></div>
              <div class="span3"><a href="logs.php" class="btn btn-block"><i class="dashboard-icons current_work_dashboard"></i><span class="dasboard-icons-title">Attack logs</span></a></div>
              <div class="span3"><a href="settings.php" class="btn btn-block"><i class="dashboard-icons settings_dashboard"></i><span class="dasboard-icons-title">API Settings</span></a></div>
              <div class="span3"><a href="methods.php" class="btn btn-block"><i class="dashboard-icons lightbulb_dashboard"></i><span class="dasboard-icons-title">Methods</span></a></div>
            </div>
          </div>
          <div class="box">
            <div class="header">
              <h4><span class="icon_charts"></span>Welcome <?php echo htmlspecialchars($_SESSION['Username']); ?></h4>
            </div>
            <div class="content pad">
              This is the universal API plugin. This neat plugin lets you create your OWN API's with your OWN servers.
              This eliminates the risk of third parties and ensures the highest possible quality. To get started you will have to add your own servers.
              Then you will have to configure the API settings and you are ready to go!
              The GUI has been developed to be as easy as possible and will let you have your own API in no time!
              The customer parameter is the place where you put your customers session username or something similar.
              Your API link is: <code>
              <?php $data = $user->returnData($_SESSION['Username']); echo Config::Read('BASEURL') . '/send.php?ip=$ip&port=$port&time=$time&method=$method&key=' . $data['accesskey'] . '&customer=$ursessionvar'; ?></code>
              
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