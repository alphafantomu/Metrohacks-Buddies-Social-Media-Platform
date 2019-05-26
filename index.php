

<?php
ini_set('session.save_path',realpath(dirname($_SERVER['DOCUMENT_ROOT']) . '/tmp'));
ini_set('session.gc_probability', 1);
session_start();
	if (isset($_SESSION["sessionId"])) {
		header("Location: https://alphaorigin.xyz/Chat1.php");
	};
?>
<!DOCTYPE html>
<html>
	<head> 
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
			<title> Buddy  </title>
			<link rel="stylesheet" href="/Styles/Page.css">
	</head>
	<body>
				<br>
				<br>
				<br>
		<header style="text-align:center"> Buddy </header>
		<h1>
			<center><img src="/Images/coollogo.png" alt="Buddy" width="150" height="145"></center>
		</h1>
			<script src="https://alphaorigin.xyz/Validity.js"></script>
		<p>
					<br>
			<!DOCTYPE html>

			<div class="container">
				<form method = "POST" action = "https://alphaorigin.xyz/MakeFriends/login.php" enctype="multipart/form-data">
					<center><input type="text" placeholder="Username" name="username" required></center>
						<br>
					<center><input type="password" placeholder="Password" name="password" required></center>
						<br>
          <center></body></text></body><label style=height: 100px; width: 200px; color:#FF0000; type="Error"><?php echo $_GET["error_msg"]; ?></label></center>
					<br>
					<center><label> <input type="checkbox" checked="checked" name="remember">Remember me</label></center>
						<br>
				
					<center><button type="submit" value = "Submit">Login</button></center
				</form>
			</div>
			<center><div class="container" style="background-color:#f1f1f1"></center>
					<br>
				<center>Do you not have an account? </center>
				<center><a href="https://alphaorigin.xyz/Register.php"> Register</a></center>
			</div>
		</p>
	</body>
</html>
