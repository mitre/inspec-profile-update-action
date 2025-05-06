control 'SV-78593' do
  title 'The system must limit sharing of console connections.'
  desc "By default, remote console sessions can be connected to by more than one user at a time.  When multiple sessions are activated, each terminal window gets a notification about the new session. If an administrator in the VM logs in using a VMware remote console during their session, a non-administrator in the VM might connect to the console and observe the administrator's actions.  Also, this could result in an administrator losing console access to a virtual machine. For example, if a jump box is being used for an open console session and the admin loses connection to that box, then the console session remains open. Allowing two console sessions permits debugging via a shared session.  For highest security, only one remote console session at a time should be allowed."
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the RemoteDisplay.maxConnections value and verify it is set to 1.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.maxConnections

If the virtual machine advanced setting RemoteDisplay.maxConnections does not exist or is not set to 1, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the RemoteDisplay.maxConnections value and set it to 1.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name RemoteDisplay.maxConnections -Value 1

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.maxConnections | Set-AdvancedSetting -Value 1'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64103'
  tag rid: 'SV-78593r1_rule'
  tag stig_id: 'VMCH-06-000033'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70031r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
