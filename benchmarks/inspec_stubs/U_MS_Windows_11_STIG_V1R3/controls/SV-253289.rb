control 'SV-253289' do
  title 'The Secondary Logon service must be disabled on Windows 11.'
  desc 'The Secondary Logon service provides a means for entering alternate credentials, typically used to run commands with elevated privileges. Using privileged credentials in a standard user session can expose those credentials to theft.'
  desc 'check', 'Run "Services.msc".

Locate the "Secondary Logon" service.

If the "Startup Type" is not "Disabled" or the "Status" is "Running", this is a finding.'
  desc 'fix', 'Configure the "Secondary Logon" service "Startup Type" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56742r828949_chk'
  tag severity: 'medium'
  tag gid: 'V-253289'
  tag rid: 'SV-253289r828951_rule'
  tag stig_id: 'WN11-00-000175'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56692r828950_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
