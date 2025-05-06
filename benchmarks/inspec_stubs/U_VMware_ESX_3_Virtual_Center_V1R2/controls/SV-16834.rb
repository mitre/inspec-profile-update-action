control 'SV-16834' do
  title 'Clipboard capabilities (copy and paste) are enabled for virtual machines.'
  desc 'Several security issues arise with the clipboard. The first is that the system administrator might turn on the clipboard transfer and use it.  However, deselecting the clipboard check box will not turn off the function, since a reboot is required. So, the clipboard function is still active. Therefore, transferring text objects, such as a password from one clipboard to another, in any direction between the virtual machine and the host operating system is possible. Secondly, this breaks the virtual machine isolation. This may cause information leakage and potentially infect other operating systems if the text is a string that can be run as a command or URL. As a result of these behaviors, all clipboard capabilities should be disabled within the virtual machine.'
  desc 'check', '1. Login to VirtualCenter with the VI Client and select a virtual machine from the inventory panel.
The configuration page for the virtual machine appears with the Summary tab displayed.
2. Click Edit Settings.
3. Click Options > Advanced > Configuration Parameters to open the Configuration Parameters dialog box.
4. The result should appear as follows:
Isolation.tools.copy.disable 			true
Isolation.tools.paste.disable 			true
Isolation tools.setGUIOptions.enable 	false
If these are not configured, this is a finding.'
  desc 'fix', 'Disable the clipboard capabilities in all virtual machines.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16252r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15893'
  tag rid: 'SV-16834r1_rule'
  tag stig_id: 'ESX0970'
  tag gtitle: 'Clipboard capabilities are enabled'
  tag fix_id: 'F-15853r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
