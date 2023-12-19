control 'SV-77779' do
  title 'The virtual switch MAC Address Change policy must be set to reject.'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing. Reject MAC Changes can be set at the vSwitch and/or the Portgroup level. You can override switch level settings at the Portgroup level.'
  desc 'check', 'From the vSphere Client go to Configuration >> Networking >> vSphere Standard Switch.  View the properties on each virtual switch and port group and verify "MAC Address Changes" is set to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

If the "MAC Address Changes" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Configuration >> Networking >> vSphere Standard Switch.  For each virtual switch go to properties and change "MAC Address Changes" to reject for the switch and each port group.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false
Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true'
  impact 0.7
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64023r1_chk'
  tag severity: 'high'
  tag gid: 'V-63289'
  tag rid: 'SV-77779r1_rule'
  tag stig_id: 'ESXI-06-000060'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
