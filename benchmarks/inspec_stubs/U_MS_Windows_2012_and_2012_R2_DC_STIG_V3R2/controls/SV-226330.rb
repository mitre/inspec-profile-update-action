control 'SV-226330' do
  title 'The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.'
  desc 'The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts.  NTLM, which is less secure, is retained in later Windows versions  for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it.  It is also used to authenticate logons to stand-alone computers that are running later versions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: LmCompatibilityLevel

Value Type: REG_DWORD
Value: 5'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28032r476834_chk'
  tag severity: 'high'
  tag gid: 'V-226330'
  tag rid: 'SV-226330r569184_rule'
  tag stig_id: 'WN12-SO-000067'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28020r476835_fix'
  tag 'documentable'
  tag legacy: ['SV-52865', 'V-1153']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
