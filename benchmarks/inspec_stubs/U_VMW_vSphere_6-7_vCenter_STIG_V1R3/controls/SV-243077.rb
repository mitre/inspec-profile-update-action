control 'SV-243077' do
  title 'The vCenter Server must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of denial-of-service (DoS) attacks by enabling Network I/O Control (NIOC).'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to Networking >> select a distributed switch >> Configure >> Settings >> Properties. 

View the "Properties" pane and verify Network I/O Control is enabled.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDSwitch | select Name,@{N="NIOC Enabled";E={$_.ExtensionData.config.NetworkResourceManagementEnabled}}

If Network I/O Control is disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Networking >> select a distributed switch >> Configure >> Settings >> Properties. 

In the "Properties" pane, click "Edit" and change Network I/O Control to enabled.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

(Get-VDSwitch "VDSwitch Name" | Get-View).EnableNetworkResourceManagement($true)'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46352r816835_chk'
  tag severity: 'medium'
  tag gid: 'V-243077'
  tag rid: 'SV-243077r816836_rule'
  tag stig_id: 'VCTR-67-000007'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46309r719473_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
