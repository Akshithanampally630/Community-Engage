<?php
$conn = new mysqli("localhost", "root", "akshitha@630", "CommuityEngage");

$data = json_decode(file_get_contents("php://input"), true);
$userID = $data["userID"];
$eventID = $data["eventID"];
$amount = $data["amount"];
$paymentMethod = $data["paymentMethod"];

$sql = "INSERT INTO Donations (UserID, EventID, Amount, PaymentMethod) 
        VALUES ('$userID', '$eventID', '$amount', '$paymentMethod')";

if ($conn->query($sql) === TRUE) {
    echo "Donation Successful!";
} else {
    echo "Error: " . $conn->error;
}

$conn->close();
?>
