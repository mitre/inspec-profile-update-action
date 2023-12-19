control 'SV-226354' do
  title 'The Microsoft FTP service must not be installed unless required.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'If the server has the role of an FTP server, this is NA.

Run "Services.msc".

If the "Microsoft FTP Service" (Service name: FTPSVC) is installed and not disabled, this is a finding.'
  desc 'fix', 'Remove or disable the "Microsoft FTP Service" (Service name: FTPSVC).   

To remove the "FTP Server" role from a system:
Start "Server Manager"
Select the server with the "FTP Server" role.
Scroll down to "ROLES AND FEATURES" in the left pane.
Select "Remove Roles and Features" from the drop down "TASKS" list.
Select the appropriate server on the "Server Selection" page, click "Next".
De-select "FTP Server" under "Web Server (IIS).
Click "Next" and "Remove" as prompted.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28056r476906_chk'
  tag severity: 'medium'
  tag gid: 'V-226354'
  tag rid: 'SV-226354r569184_rule'
  tag stig_id: 'WN12-SV-000101'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-28044r476907_fix'
  tag 'documentable'
  tag legacy: ['SV-52237', 'V-26602']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
