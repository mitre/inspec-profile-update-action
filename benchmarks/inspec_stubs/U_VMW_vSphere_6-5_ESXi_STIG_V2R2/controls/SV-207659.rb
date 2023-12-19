control 'SV-207659' do
  title 'The virtual switch MAC Address Change policy must be set to reject on the ESXi host.'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing. Reject MAC Changes can be set at the vSwitch and/or the Portgroup level. You can override switch level settings at the Portgroup level.'
  desc 'check', 'From the vSphere Web Client go to Configure >> Networking >> Virtual Switches. View the properties on each virtual switch and port group and verify "MAC Address Changes" is set to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

If the "MAC Address Changes" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Configure >> Networking >> Virtual Switches. For each virtual switch and port group click Edit settings and change "MAC Address Changes" to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false
Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true'
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7914r364376_chk'
  tag severity: 'high'
  tag gid: 'V-207659'
  tag rid: 'SV-207659r388482_rule'
  tag stig_id: 'ESXI-65-000060'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7914r364377_fix'
  tag 'documentable'
  tag legacy: ['V-94067', 'SV-104153']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
