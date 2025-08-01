control 'SV-216830' do
  title 'The vCenter Server for Windows must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of Denial of Service (DoS) attacks by enabling Network I/O Control (NIOC).'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Configure >> Settings >> Properties. View the Properties pane and verify Network I/O Control is enabled.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDSwitch | select Name,@{N="NIOC Enabled";E={$_.ExtensionData.config.NetworkResourceManagementEnabled}}

If Network I/O Control is disabled, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Configure >> Settings >> Properties. In the Properties pane click "Edit" and change Network I/O Control to enabled.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

(Get-VDSwitch "DVSwitch Name" | Get-View).EnableNetworkResourceManagement($true)'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18061r366204_chk'
  tag severity: 'medium'
  tag gid: 'V-216830'
  tag rid: 'SV-216830r612237_rule'
  tag stig_id: 'VCWN-65-000007'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18059r366205_fix'
  tag 'documentable'
  tag legacy: ['SV-104557', 'V-94727']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
