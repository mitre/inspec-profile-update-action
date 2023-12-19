control 'SV-250744' do
  title 'The system must set a timeout for all thick-client logins without activity.'
  desc 'An inactivity timeout must be set for the vSphere Client (Thick Client). This client-side setting can be changed by users, so this must be set by default and re-audited. Automatic session termination minimizes risk and reduces the potential for unauthorized access to vCenter.'
  desc 'check', 'On each Windows computer with the vSphere Client installed, verify:
A 15 minute (maximum) timeout is set in the VpxClient.exe.config file:
Locate the VpxClient.exe.config file using the Windows OS search facility. Next, right click on VpxClient.exe.config and edit the file using an editor, such as Notepad. In the <cmdlineFallback>... </cmdlineFallback> section, verify the setting <inactivityTimeout>X</inactivityTimeout> where X is the (maximum=15) number of minutes before the vSphere Client will automatically disconnect from the server. 

Verify the timeout that the vSphere Client executable is started with is an execution flag:
Locate the vSphere Client executable icon on the desktop, right click, and select properties. Verify the presence of "-inactivityTimeout 15" in the command.

If either of the above methods are invoked and the timeout interval exceeds 15 minutes, this is a finding.'
  desc 'fix', 'On each Windows computer with the vSphere Client installed:
Set a 15 minute (maximum) timeout in the VpxClient.exe.config file:
Locate the VpxClient.exe.config file using the Windows OS search facility. Next, right click on VpxClient.exe.config and edit the file using an editor, such as Notepad. In the <cmdlineFallback>... </cmdlineFallback> section, modify the <inactivityTimeout>X</inactivityTimeout> where X is the (maximum=15) number of minutes before the vSphere Client will automatically disconnect from the server. Exit, saving the file.

Set a 15 minute (maximum) timeout execution flag when starting the vSphere Client executable:
Locate the vSphere Client executable icon on the desktop, right click, and select properties. Add "-inactivityTimeout X", where X is the (maximum=15) number of minutes before the vSphere Client will automatically disconnect from the server.'
  impact 0.5
  ref 'DPMS Target VMware vCenter Server Version 5'
  tag check_id: 'C-54179r799920_chk'
  tag severity: 'medium'
  tag gid: 'V-250744'
  tag rid: 'SV-250744r799922_rule'
  tag stig_id: 'VCENTER-000027'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-54133r799921_fix'
  tag 'documentable'
  tag legacy: ['SV-51421', 'V-39563']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
