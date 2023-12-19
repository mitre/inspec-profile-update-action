control 'SV-205919' do
  title 'Windows Server 2019 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.'
  desc 'The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it. It is also used to authenticate logons to standalone or nondomain-joined computers that are running later versions.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: LmCompatibilityLevel

Value Type: REG_DWORD
Value: 0x00000005 (5)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6184r356119_chk'
  tag severity: 'high'
  tag gid: 'V-205919'
  tag rid: 'SV-205919r857347_rule'
  tag stig_id: 'WN19-SO-000310'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6184r356120_fix'
  tag 'documentable'
  tag legacy: ['SV-103389', 'V-93301']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
