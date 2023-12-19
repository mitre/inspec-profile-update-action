control 'SV-33725' do
  title 'The Microsoft FTP service must not be installed unless required.'
  desc 'Unnecessary Services increase the attack surface of a system.  Some of these services may not support required levels of authentication or encryption.'
  desc 'check', 'If the server has the role of an FTP server, this is NA.

Verify the service is not installed or is disabled. 

Select "Start".
Select "Run".
Enter "Services.msc".
Respond to any User Account Control prompts.

If the "Microsoft FTP Service" (Service name: msftpsvc) is installed and not disabled, this is a finding.'
  desc 'fix', 'Uninstall or disable the Microsoft FTP Service (msftpsvc) service.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-34148r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26602'
  tag rid: 'SV-33725r2_rule'
  tag stig_id: 'WINSV-000101'
  tag gtitle: 'Microsoft FTP Service Disabled'
  tag fix_id: 'F-29838r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
