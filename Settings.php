
<?php
ini_set('session.save_path',realpath(dirname($_SERVER['DOCUMENT_ROOT']) . '/tmp'));
ini_set('session.gc_probability', 1);
session_start();
	if (!isset($_SESSION["sessionId"])) {
		header("Location: https://alphaorigin.xyz");
		exit(0);
	};
?>
<html>
	<head> 
			<title> Buddy </title>
			<link href='https://fonts.googleapis.com/css?family=Comfortaa' rel='stylesheet'>
		<style>
			input {
			font-family: 'Comfortaa'; font-size: 18px;
    		}
			header {
			font-family: 'Comfortaa';font-size: 28px;
			font-weight: bold;
			}
			body {
			font-family: 'Comfortaa'; font-size: 17px;
			}
			button {
			font-family: 'Comfortaa'; font-size: 15px;
    		}
		</style>    
			<link rel="stylesheet" href="Styles/Page.css">

	</head>
<body>
<header style="text-align:center"> Buddy </header>
<h1>
<center><img src="/Images/coollogo.png" alt="Buddy" width="150" height="150"></center>
</h1>
  
<script src="https://alphaorigin.xyz/Validity.js"></script>
<br>
<center><font size="3">Settings</font></center>
<p>
  
<center></body></text></body><label style=height: 100px; width: 200px; color:#FF0000; type="Error"><?php echo $_GET["error_msg"]; ?></label></center>
<form method = "POST" action = "https://alphaorigin.xyz/MakeFriends/logout.php" enctype="multipart/form-data">
<center><button type="submit" value = "Submit2" style="height: 30px; width: 150px" >Sign Out</button></center>
</form>
        <br>
<form method = "POST" action = "https://alphaorigin.xyz/MakeFriends/deleteaccount.php" enctype="multipart/form-data">
<center><button type="submit" value = "Submit3" style="height: 30px; width: 150px">Delete Account</button></center>
</form>
</p>
</body>
</html>

