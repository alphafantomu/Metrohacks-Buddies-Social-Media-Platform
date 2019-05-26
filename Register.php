
<?php
ini_set('session.save_path',realpath(dirname($_SERVER['DOCUMENT_ROOT']) . '/tmp'));
ini_set('session.gc_probability', 1);
session_start();
	if (isset($_SESSION["sessionId"])) {
		header("Location: https://alphaorigin.xyz/Chat1.php");
		exit(0);
	};
?>
<!DOCTYPE html>
<html>
    <head> 
			<title> Buddy </title>
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
			<link rel="stylesheet" href="Styles/Page.css">

	</head>
	<body>
		<p>
					<br>
					<br>
					<center><header>Buddy</header></center>
					<br>
					<center><img src="https://codehs.com/uploads/5f213473abce718dd04ecb6638a4313e" alt="Buddy" width="150" height="145"></center>   
					<div class="Name">
					<br>
					<br>
					<form method = "POST" action = "https://alphaorigin.xyz/MakeFriends/register.php" enctype="multipart/form-data">
					<center></body></text></body><label style=height: 100px; width: 200px; color:#FF0000; type="Error"><?php echo $_GET["error_msg"]; ?></label></center>
					<center><input type="text" placeholder="Name" name="name" required></center>
					<br>      
						<center><input type="text" placeholder="Age" name="age" required></center>
					<br>
						<center><input type="text" placeholder="Email" name="email" required></center>
					<br>
						<center><input type="text" placeholder="Username" name="username" required></center>
					<br>
					<center><input type="password" placeholder="Password" name="password" required></center>
					<br>
					<center><label> <input type="checkbox" checked="checked" name="remember"> Remember me </label></center>
					<br>
					<center><button type="submit" value = "Submit1">Sign Up</button></center>
					<br>
					
			</div>
				<center><div class="container" style="background-color:#f1f1f1"></center>
					<br>
				<center>Do you want to return to log in? </center>
				<center><a href="https://alphaorigin.xyz/"> Return to Login </a></center>
			</div>
		</p>
	</body>
</html>
