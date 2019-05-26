
<?php
	ini_set('session.save_path',realpath(dirname($_SERVER['DOCUMENT_ROOT']) . '/tmp'));
ini_set('session.gc_probability', 1);
	session_start();
	function getUserIpAddr(){
		if(!empty($_SERVER['HTTP_CLIENT_IP'])){
			//ip from share internet
			$ip = $_SERVER['HTTP_CLIENT_IP'];
		}elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){
			//ip pass from proxy
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		}else{
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		return $ip;
	}
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        if (isset($_POST["username"]) and isset($_POST["password"]) and isset($_POST["name"]) and isset($_POST["email"]) and isset($_POST["age"])) {
			$username = $_POST["username"];
			$password = $_POST["password"];
			$name = $_POST["name"];
			$email = $_POST["email"];
			$age = $_POST["age"];
			if (!isset($_SESSION["sessionId"])) {
				function httpPost($url, $data) {
					$curl = curl_init($url);
					curl_setopt($curl, CURLOPT_POST, true);
					curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
					curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
					$response = curl_exec($curl);
					curl_close($curl);
					return $response;
				};
				$request_data = array(
					"ip-address" => getUserIpAddr(),
					"sent_info" => array(
						"username" => $username,
						"password" => $password,
						"name" => $name,
						"email" => $email,
						"age" => $age,
					),
				);
				$status = httpPost("http://alphaorigin.xyz:9000/Register", json_encode($request_data));
				$status_data = json_decode($status, true);
				echo $status_data["message"];
				if ($status_data['status'] == true) {
					//$_SESSION['session_id'] = $status_data["sessionId"];
					//echo $status_data["message"];
					
					header("Location: https://alphaorigin.xyz/Chat1.php");
				} elseif ($status_data['status'] == false) {
					
					header('Location: https://alphaorigin.xyz/Register.php?error_msg='.$status_data["message"]);
					exit;
				};
				exit;
			};
        };
	};
	echo 'Request method not valid or post body unknown';
	header('Location: https://alphaorigin.xyz/Register.php?error_msg=Request method not valid or post body unknown');
	exit;
?>
