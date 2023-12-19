control 'SV-77781' do
  title 'The virtual switch Promiscuous Mode policy must be set to reject.'
  desc 'When promiscuous mode is enabled for a virtual switch all virtual machines connected to the Portgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that Portgroup. Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting. Promiscuous mode can be set at the vSwitch and/or the Portgroup level. You can override switch level settings at the Portgroup level.'
  desc 'check', 'From the vSphere Client go to Configuration >> Networking >> vSphere Standard Switch.  View the properties on each virtual switch and port group and verify "Promiscuous Mode" is set to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

If the "Promiscuous Mode" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Configuration >> Networking >> vSphere Standard Switch.  For each virtual switch go to properties and change "Promiscuous Mode" to reject for the switch and each port group.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64025r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63291'
  tag rid: 'SV-77781r1_rule'
  tag stig_id: 'ESXI-06-000061'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
