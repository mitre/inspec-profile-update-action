control 'SV-243111' do
  title 'The vCenter Server must configure the vSAN Datastore name to a unique name.'
  desc 'A vSAN Datastore name by default is "vsanDatastore". If more than one vSAN cluster is present in vCenter, both datastores will have the same name by default, potentially leading to confusion and manually misplaced workloads.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Client, go to Hosts and Clusters >> select a vSAN Enabled Cluster >> Datastores.

Review the datastores. 

Identify any datastores with "vSAN" as the datastore type.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){
Write-Host "vSAN Enabled Cluster found"
Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match "vsan"}
}
else{
Write-Host "vSAN is not enabled, this finding is not applicable"
}

If vSAN is enabled and the datastore is named "vsanDatastore", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> select a vSAN Enabled Cluster >> Datastores. 

Right-click on the datastore named "vsanDatastore" and select "Rename". 

Rename the datastore based on site-specific naming standards.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

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
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46386r719574_chk'
  tag severity: 'medium'
  tag gid: 'V-243111'
  tag rid: 'SV-243111r879887_rule'
  tag stig_id: 'VCTR-67-000055'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46343r719575_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
