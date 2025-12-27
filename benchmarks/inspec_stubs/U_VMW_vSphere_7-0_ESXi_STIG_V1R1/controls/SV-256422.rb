control 'SV-256422' do
  title 'All port groups on standard switches must be configured to reject guest promiscuous mode requests.'
  desc 'When promiscuous mode is enabled for a virtual switch, all virtual machines (VMs) connected to the Portgroup have the potential to read all packets across that network (only the virtual machines connected to that Portgroup).

Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting. Promiscuous mode can be set at the vSwitch and/or the Portgroup level. Switch-level settings can be overridden at the Portgroup level.'
  desc 'check', 'Note: This control addresses ESXi standard switches. Distributed switches are addressed in the vCenter STIG. If there is no standard switch on the ESXi host, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

On each standard switch, click the "..." button next to each port group. Click View Settings >> Policies tab. 

Verify "Promiscuous Mode" is set to "Reject".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VirtualSwitch -Standard | Get-SecurityPolicy
Get-VirtualPortGroup -Standard | Get-SecurityPolicy

If the "Promiscuous Mode" policy is set to "Accept" (or "true", via PowerCLI), this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> Networking >> Virtual Switches.

On each standard switch, click the "..." button next to each port group. Click Edit Settings >> Security tab. 

Set "Promiscuous Mode" to "Reject".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VirtualSwitch -Standard | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
Get-VirtualPortGroup -Standard | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60097r886045_chk'
  tag severity: 'medium'
  tag gid: 'V-256422'
  tag rid: 'SV-256422r886047_rule'
  tag stig_id: 'ESXI-70-000061'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60040r886046_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
