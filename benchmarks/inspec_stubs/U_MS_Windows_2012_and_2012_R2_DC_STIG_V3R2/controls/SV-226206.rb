control 'SV-226206' do
  title 'Basic authentication for RSS feeds over HTTP must be turned off.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

Value Name: AllowBasicAuthInClear

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> RSS Feeds -> "Turn on Basic feed authentication over HTTP" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27908r475941_chk'
  tag severity: 'medium'
  tag gid: 'V-226206'
  tag rid: 'SV-226206r569184_rule'
  tag stig_id: 'WN12-CC-000106'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27896r475942_fix'
  tag 'documentable'
  tag legacy: ['SV-51749', 'V-36709']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
