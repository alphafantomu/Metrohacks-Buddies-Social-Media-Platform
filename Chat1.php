
<?php
ini_set('session.save_path',realpath(dirname($_SERVER['DOCUMENT_ROOT']) . '/tmp'));
ini_set('session.gc_probability', 1);
session_start();
	if (!isset($_SESSION["sessionId"])) {
		header("Location: https://alphaorigin.xyz?error_msg=".$_SESSION["sessionId"]);
		exit(0);
	};
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<link href='https://fonts.googleapis.com/css?family=Comfortaa' rel='stylesheet'>
<style>
         input[type="submit"]
          {
          font-family: 'Comfortaa';font-size: 28px;
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
    			<link rel="stylesheet" href="/Styles/Page.css">

<title> Chat Room</title>

</head>
 
<body>
  <div id="container" align = "right">
		<form method = "POST" action = "https://alphaorigin.xyz/Settings.php" enctype="multipart/form-data" target="_blank">
      <button type="submit" value = "Settings">Settings</button>

    </form>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>
        <br>  

  <center></body></text></body><label style=height: 100px; width: 200px; color:#FF0000; type="Error"><?php echo $_GET["error_msg"]; ?></label></center>
<text align = "right"><label> Hello </label></text>
  <img src="https://codehs.com/uploads/669650c1ef337b1033f8b970e9c3250d" alt="User 1" width="130" height="220 " align="right">
<img src="https://codehs.com/uploads/178deb1a58f5893e5624f88e338eac7b" alt="User 1" width="130" height="220 " align="left">

</div>
<div>
<text align = "left"><label> Hi </label></text>
  <center></body></text></body><label style=height: 100px; width: 200px; color:#FF0000; type="Error"><?php echo $_GET["error_msg"]; ?></label></center>
</div>


      <div id="chatbox"></div>

      <form name="message" action="">
          <center><input name="usermsg" type="text" id="usermsg" size="30"/> </center>
          <center><input name="submitmsg" type="submit"  id="submitmsg" value="Send"></center>
      </form>
  </div>





</body>

</script>
</body>
</html>


