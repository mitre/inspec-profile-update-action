control 'SV-207660' do
  title 'The virtual switch Promiscuous Mode policy must be set to reject on the ESXi host.'
  desc 'When promiscuous mode is enabled for a virtual switch all virtual machines connected to the Portgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that Portgroup. Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting. Promiscous mode can be set at the vSwitch and/or the Portgroup level. You can override switch level settings at the Portgroup level.'
  desc 'check', 'From the vSphere Web Client go to Configure >> Networking >> Virtual Switches. View the properties on each virtual switch and port group and verify "Promiscuous Mode" is set to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy

If the "Promiscuous Mode" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Configure >> Networking >> Virtual Switches. For each virtual switch and port group click Edit settings and change "Promiscuous Mode" to reject.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7915r364379_chk'
  tag severity: 'medium'
  tag gid: 'V-207660'
  tag rid: 'SV-207660r388482_rule'
  tag stig_id: 'ESXI-65-000061'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7915r364380_fix'
  tag 'documentable'
  tag legacy: ['V-94069', 'SV-104155']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
