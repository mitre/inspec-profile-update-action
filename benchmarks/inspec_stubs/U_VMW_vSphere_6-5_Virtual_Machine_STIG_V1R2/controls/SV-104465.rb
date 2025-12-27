control 'SV-104465' do
  title 'Access to virtual machines through the dvfilter network APIs must be controlled.'
  desc 'An attacker might compromise a VM by making use the dvFilter API. Configure only those VMs to use the API that need this access.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Look for settings with the format ethernet*.filter*.name.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name "ethernet*.filter*.name*"

If the virtual machine advanced setting ethernet*.filter*.name exists and dvfilters are not in use, this is a finding.

If the virtual machine advanced setting ethernet*.filter*.name exists and the value is not valid, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Look for settings with the format ethernet*.filter*.name. Ensure only required VMs use this setting.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name ethernetX.filterY.name | Remove-AdvancedSetting

Note:  Change the X and Y values to match the specific setting in your environment.'
  impact 0.3
  ref 'DPMS Target VMWare Virtual Machine 6.5'
  tag check_id: 'C-93825r1_chk'
  tag severity: 'low'
  tag gid: 'V-94635'
  tag rid: 'SV-104465r1_rule'
  tag stig_id: 'VMCH-65-000041'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-100753r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
