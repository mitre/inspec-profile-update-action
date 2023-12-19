control 'SV-258773' do
  title 'The ESXi host must configure virtual switch security policies to reject promiscuous mode requests.'
  desc 'When promiscuous mode is enabled for a virtual switch, all virtual machines (VMs) connected to the Portgroup have the potential to read all packets across that network (only the virtual machines connected to that Portgroup).

Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting. Promiscuous mode can be set at the vSwitch and/or the Portgroup level. Switch-level settings can be overridden at the Portgroup level.'
  desc 'check', %q(This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

On each standard switch, click the '...' button next to each port group and select "Edit Settings".

Click the "Security" tab. Verify that "Promiscuous Mode" is set to "Reject" and that "Override" is not checked.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy
Get-VirtualPortGroup | Get-SecurityPolicy | Select-Object *

If the "Promiscuous Mode" policy is set to "Accept" (or "true", via PowerCLI) or the security policy inherited from the virtual switch is overridden, this is a finding.)
  desc 'fix', %q(From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

On each standard switch, click "Edit" and select Security.

Set "Promiscuous Mode" to "Reject". Click "OK".

For each port group, click the '...' button and select "Edit Settings" then Security.

Set "Promiscuous Mode" to "Reject" and uncheck the "Override" box. Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true)
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62513r933378_chk'
  tag severity: 'medium'
  tag gid: 'V-258773'
  tag rid: 'SV-258773r933380_rule'
  tag stig_id: 'ESXI-80-000218'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62422r933379_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
