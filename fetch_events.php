<?php
$conn = new mysqli("localhost", "root", "akshitha@360", "CommunityEngage");

$sql = "SELECT * FROM Events";
$result = $conn->query($sql);

$events = [];
while ($row = $result->fetch_assoc()) {
    $events[] = $row;
}

$conn->close();
echo json_encode($events);
?>