control 'SV-258713' do
  title 'Virtual machines (VMs) must disable access through the "dvfilter" network Application Programming Interface (API).'
  desc 'An attacker might compromise a VM by using the "dvFilter" API. Configure only VMs that need this access to use the API.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the settings with the format "ethernet*.filter*.name" do not exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name "ethernet*.filter*.name*"

If the virtual machine advanced setting "ethernet*.filter*.name" exists and dvfilters are not in use, this is a finding.

If the virtual machine advanced setting "ethernet*.filter*.name" exists and the value is not valid, this is a finding.'
  desc 'fix', %q(For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Look for settings with the format "ethernet*.filter*.name".

Ensure only required VMs use this setting.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name ethernetX.filterY.name | Remove-AdvancedSetting

Note: Change the X and Y values to match the specific setting in the organization's environment.

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.)
  impact 0.3
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62453r933198_chk'
  tag severity: 'low'
  tag gid: 'V-258713'
  tag rid: 'SV-258713r933200_rule'
  tag stig_id: 'VMCH-80-000200'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62362r933199_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
