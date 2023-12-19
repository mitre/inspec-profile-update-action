control 'SV-216834' do
  title 'The vCenter Server for Windows must disable the distributed virtual switch health check.'
  desc 'Network Healthcheck is disabled by default. Once enabled, the healthcheck packets contain information on host#, vds#, port#, which an attacker would find useful. It is recommended that network healthcheck be used for troubleshooting, and turned off when troubleshooting is finished.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Configure >> Settings >> Health Check. View the health check pane and verify both checks are disabled.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
$vds = Get-VDSwitch
$vds.ExtensionData.Config.HealthCheckConfig

If the health check feature is enabled on distributed switches and is not on temporarily for troubleshooting purposes, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Configure >> Settings >> Health Check. Click the "Edit" button and disable both health checks.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-View -ViewType DistributedVirtualSwitch | ?{($_.config.HealthCheckConfig | ?{$_.enable -notmatch "False"})}| %{$_.UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))}'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18065r366216_chk'
  tag severity: 'low'
  tag gid: 'V-216834'
  tag rid: 'SV-216834r612237_rule'
  tag stig_id: 'VCWN-65-000012'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18063r366217_fix'
  tag 'documentable'
  tag legacy: ['SV-104565', 'V-94735']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
