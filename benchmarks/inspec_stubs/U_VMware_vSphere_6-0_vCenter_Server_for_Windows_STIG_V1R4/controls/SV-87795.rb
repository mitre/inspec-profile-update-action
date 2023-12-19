control 'SV-87795' do
  title 'The system must configure the VSAN Datastore name to a unique name.'
  desc 'VSAN Datastore name by default is "vsanDatastore". If more than one VSAN cluster is present in vCenter both datastores will have the same name by default potentially leading to confusion and manually misplaced workloads.'
  desc 'check', 'If no clusters are enabled for VSAN, this is not applicable.

From the vSphere Web Client go to Host and Clusters >> Select a Cluster >> Related Objects >> Datastores. Review the datastores. Identify any datastores with "vsan" as the datastore type.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){
Write-Host "VSAN Enabled Cluster found"
Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match "vsan"}
}
else{
Write-Host "VSAN is not enabled, this finding is not applicable"
}

If VSAN is Enabled and the datastore is named "vsanDatastore" this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Host and Clusters > Select a Cluster > Related Objects > Datastores. Right click on the datastore named "vsanDatastore" and select "Rename". Rename the datastore based on operational naming standards.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){
Write-Host "VSAN Enabled Cluster found"
$Clusters = Get-Cluster | where {$_.VsanEnabled}   
Foreach ($clus in $clusters){
 $clus | Get-Datastore | where {$_.type -match "vsan"} | Set-Datastore -Name $(($clus.name) + "_VSAN_Datastore")
}
}
else{
Write-Host "VSAN is not enabled, this finding is not applicable"
}'
  impact 0.3
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-73277r2_chk'
  tag severity: 'low'
  tag gid: 'V-73143'
  tag rid: 'SV-87795r1_rule'
  tag stig_id: 'VCWN-06-000054'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-79589r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
