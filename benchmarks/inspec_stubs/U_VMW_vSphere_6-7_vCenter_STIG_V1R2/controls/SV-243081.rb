control 'SV-243081' do
  title 'The vCenter Server must disable the distributed virtual switch health check.'
  desc 'Network Healthcheck is disabled by default. Once enabled, the healthcheck packets contain information on host#, vds#, and port#, which an attacker would find useful. It is recommended that network healthcheck be used for troubleshooting and turned off when troubleshooting is finished.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to Networking >> select a distributed switch >> Configure >> Settings >> Health Check. 

View the health check pane and verify that the "VLAN and MTU" and "Teaming and failover" checks are disabled.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

$vds = Get-VDSwitch
$vds.ExtensionData.Config.HealthCheckConfig

If the health check feature is enabled on distributed switches and is not on temporarily for troubleshooting purposes, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Networking >> select a distributed switch >> Configure >> Settings >> Health Check. 

Click "Edit" and disable the "VLAN and MTU" and "Teaming and failover" checks.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-View -ViewType DistributedVirtualSwitch | ?{($_.config.HealthCheckConfig | ?{$_.enable -notmatch "False"})}| %{$_.UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))}'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46356r816837_chk'
  tag severity: 'medium'
  tag gid: 'V-243081'
  tag rid: 'SV-243081r816839_rule'
  tag stig_id: 'VCTR-67-000012'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46313r816838_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
