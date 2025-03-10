control 'SV-83309' do
  title 'The Microsoft FTP service must not be installed unless required.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'If the server has the role of an FTP server, this is NA.

Run "Services.msc".

If the "FTP Publishing Service" (Service name: MSFTPSVC) is installed and not disabled, this is a finding.'
  desc 'fix', 'Remove or disable the "FTP Publishing Service" (Service name: MSFTPSVC).   

To remove the "FTP Server" role from a system:
Start "Server Manager"
Select "Roles" in the left pane.
In the right pane, scroll down to the "Web Server (IIS)" section.
Under "Role Services", select "Remove Role Services".
On the "Role Services" screen, de-select "FTP Publishing Service".
Click "Next" and "Remove".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-69259r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26602'
  tag rid: 'SV-83309r2_rule'
  tag stig_id: 'WINSV-000101'
  tag gtitle: 'Microsoft FTP Service Disabled'
  tag fix_id: 'F-74867r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
