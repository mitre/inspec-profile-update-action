control 'SV-78451' do
  title 'The system must disable the distributed virtual switch health check.'
  desc 'Network Healthcheck is disabled by default. Once enabled, the healthcheck packets contain information on host#, vds#, port#, which an attacker would find useful. It is recommended that network healthcheck be used for troubleshooting, and turned off when troubleshooting is finished.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Manage >> Settings >> Health Check.  View the health check pane and verify both checks are disabled.

or

From a PowerCLI command prompt while connected to the vCenter server run the following commands:

$vds = Get-VDSwitch
$vds.ExtensionData.Config.HealthCheckConfig

If the health check feature is enabled on distributed switches and is not on temporarily for troubleshooting purposes, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Manage >> Settings >> Health Check. Click the edit button and disable both health checks.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-View -ViewType DistributedVirtualSwitch | ?{($_.config.HealthCheckConfig | ?{$_.enable -notmatch "False"})}| %{$_.UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))}'
  impact 0.3
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64713r1_chk'
  tag severity: 'low'
  tag gid: 'V-63961'
  tag rid: 'SV-78451r1_rule'
  tag stig_id: 'VCWN-06-000012'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69891r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
