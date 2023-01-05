Set-AzContext -SubscriptionId "xxxxx-xxxxxxx-xxxxxxxx-xxxxx"
$alerts=Get-AzSecurityAlert | Where-Object {$_.StartTimeUtc -lt ([DateTime]'11-30-2022 10:00:20 AM') -and {$_.AlertDisplayName -eq "Network communication with a malicious machine detected","Possible outgoing denial-of-service attack detected","DDoS Attack mitigated for Public IP","DDoS Attack detected for Public IP"} -and {$_.Status -eq "Active"}}
foreach ($alert in $alerts){	
    $Name = $alert.Name
    $a = $alert.Id
    $a1 = "`""+"$a"+"`""
    $b = $a1 -split("/locations/")
    $c = $b[1] -split("/alerts/")
    $d = $c[0]
    Set-AzSecurityAlert -Name "$Name" -location "$d" -ActionType Dismiss 
}
