control 'SV-104455' do
  title 'Console access through the VNC protocol must be disabled on the virtual machine.'
  desc 'The VM console enables you to connect to the console of a virtual machine, in effect seeing what a monitor on a physical server would show. This console is also available via the VNC protocol and should be disabled.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Verify the RemoteDisplay.vnc.enabled value is set to false.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.vnc.enabled

If the virtual machine advanced setting RemoteDisplay.vnc.enabled does not exist or is not set to false, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Find the RemoteDisplay.vnc.enabled value and set it to false. If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name RemoteDisplay.vnc.enabled -Value false

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.vnc.enabled | Set-AdvancedSetting -Value false'
  impact 0.5
  ref 'DPMS Target VMWare Virtual Machine 6.5'
  tag check_id: 'C-93815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94625'
  tag rid: 'SV-104455r1_rule'
  tag stig_id: 'VMCH-65-000034'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-100743r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
