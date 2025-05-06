control 'SV-78441' do
  title 'The system must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of Denial of Service (DoS) attacks by enabling Network I/O Control (NIOC).'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Manage >> Settings >> Properties.  View the Properties pane and verify Network I/O Control is enabled.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-VDSwitch | select Name,@{N="NIOC Enabled";E={$_.ExtensionData.config.NetworkResourceManagementEnabled}}

If Network I/O Control is disabled, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Manage >> Settings >> Properties.  In the Properties pane click "Edit" and change Network I/O Control to enabled.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

(Get-VDSwitch "DVSwitch Name" | Get-View).EnableNetworkResourceManagement($true)'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64701r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63951'
  tag rid: 'SV-78441r2_rule'
  tag stig_id: 'VCWN-06-000007'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69879r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
