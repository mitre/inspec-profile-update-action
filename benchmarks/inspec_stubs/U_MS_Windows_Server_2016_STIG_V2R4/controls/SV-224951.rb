control 'SV-224951' do
  title 'Basic authentication for RSS feeds over HTTP must not be used.'
  desc 'Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.'
  desc 'check', 'The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: AllowBasicAuthInClear

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> "Turn on Basic feed authentication over HTTP" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26642r465755_chk'
  tag severity: 'medium'
  tag gid: 'V-224951'
  tag rid: 'SV-224951r569186_rule'
  tag stig_id: 'WN16-CC-000430'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26630r465756_fix'
  tag 'documentable'
  tag legacy: ['V-73579', 'SV-88243']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
