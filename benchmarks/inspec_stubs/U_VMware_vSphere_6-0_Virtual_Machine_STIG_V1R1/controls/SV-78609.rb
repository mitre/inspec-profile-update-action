control 'SV-78609' do
  title 'The system must control access to VMs through the dvfilter network APIs.'
  desc 'An attacker might compromise a VM by making use the dvFilter API. Configure only those VMs that need this access to use the API.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Look for settings with the format ethernet*.filter*.name. 

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name "ethernet*.filter*.name*"

If the virtual machine advanced setting ethernet*.filter*.name exists and dvfilters are not in use, this is a finding.

If the virtual machine advanced setting ethernet*.filter*.name exists and the value is not valid, this is a finding.'
  desc 'fix', 'From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name ethernetX.filterY.name | Remove-AdvancedSetting

Note:  Change the X and Y values to match the specific setting in your environment.'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64869r1_chk'
  tag severity: 'low'
  tag gid: 'V-64119'
  tag rid: 'SV-78609r1_rule'
  tag stig_id: 'VMCH-06-000041'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
