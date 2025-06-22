<?php
$conn = new mysqli("localhost", "root", "akshitha@630", "CommuityEngage");

$sql = "SELECT Donations.DonationID, Users.UserName, Events.EventName, Donations.Amount, Donations.DonationDate, Donations.PaymentMethod 
        FROM Donations 
        JOIN Users ON Donations.UserID = Users.UserID 
        JOIN Events ON Donations.EventID = Events.EventID";

$result = $conn->query($sql);
$donations = [];

while ($row = $result->fetch_assoc()) {
    $donations[] = $row;
}

$conn->close();
echo json_encode($donations);
?>