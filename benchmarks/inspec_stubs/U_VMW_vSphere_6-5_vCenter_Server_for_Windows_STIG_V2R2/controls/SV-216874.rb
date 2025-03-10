control 'SV-216874' do
  title 'The vCenter Server for Windows must configure the vSAN Datastore name to a unique name.'
  desc 'A vSAN Datastore name by default is "vsanDatastore". If more than one vSAN cluster is present in vCenter both datastores will have the same name by default, potentially leading to confusion and manually misplaced workloads.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Web Client go to Host and Clusters >> Select a vSAN Enabled Cluster >> Datastores. Review the datastores. 

Identify any datastores with "vsan" as the datastore type.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){
Write-Host "vSAN Enabled Cluster found"
Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match "vsan"}
}
else{
Write-Host "vSAN is not enabled, this finding is not applicable"
}

If vSAN is Enabled and the datastore is named "vsanDatastore", this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Host and Clusters >> Select a vSAN Enabled Cluster >> Datastores. Right-click on the datastore named "vsanDatastore" and select "Rename". Rename the datastore based on operational naming standards.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){
Write-Host "vSAN Enabled Cluster found"
$Clusters = Get-Cluster | where {$_.VsanEnabled} 
Foreach ($clus in $clusters){
 $clus | Get-Datastore | where {$_.type -match "vsan"} | Set-Datastore -Name $(($clus.name) + "_vSAN_Datastore")
}
}
else{
Write-Host "vSAN is not enabled, this finding is not applicable"
}'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18105r366336_chk'
  tag severity: 'medium'
  tag gid: 'V-216874'
  tag rid: 'SV-216874r612237_rule'
  tag stig_id: 'VCWN-65-000055'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18103r366337_fix'
  tag 'documentable'
  tag legacy: ['SV-104643', 'V-94813']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
