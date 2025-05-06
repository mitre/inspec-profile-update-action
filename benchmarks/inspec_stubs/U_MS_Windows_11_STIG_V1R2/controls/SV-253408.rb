control 'SV-253408' do
  title 'Basic authentication for RSS feeds over HTTP must not be used.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: AllowBasicAuthInClear

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> "Turn on Basic feed authentication over HTTP" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56861r829306_chk'
  tag severity: 'medium'
  tag gid: 'V-253408'
  tag rid: 'SV-253408r829308_rule'
  tag stig_id: 'WN11-CC-000300'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56811r829307_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
