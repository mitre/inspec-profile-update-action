control 'SV-253423' do
  title 'The convenience PIN for Windows 11 must be disabled.'
  desc 'This policy controls whether a domain user can sign in using a convenience PIN to prevent enabling (Password Stuffer).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\System

Value Name: AllowDomainPINLogon
Value Type: REG_DWORD
Value data: 0'
  desc 'fix', 'Disable the convenience PIN sign-in. 

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> Set "Turn on convenience PIN sign-in" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56876r829351_chk'
  tag severity: 'medium'
  tag gid: 'V-253423'
  tag rid: 'SV-253423r840184_rule'
  tag stig_id: 'WN11-CC-000370'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56826r840184_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
