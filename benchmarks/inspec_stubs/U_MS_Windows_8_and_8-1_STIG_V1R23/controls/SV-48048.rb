control 'SV-48048' do
  title 'The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.'
  desc 'The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts.  NTLM which is less secure, is retained in later Windows versions  for compatibility with clients and servers that are running earlier versions of Windows or applications that still use it.  It is also used to authenticate logons to stand-alone computers that are running later versions.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options. 

If the value for "Network security: LAN Manager authentication level" is not set to "Send NTLMv2 response only. Refuse LM & NTLM" (Level 5), this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: LmCompatibilityLevel

Value Type: REG_DWORD
Value: 5'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44787r1_chk'
  tag severity: 'high'
  tag gid: 'V-1153'
  tag rid: 'SV-48048r1_rule'
  tag stig_id: 'WN08-SO-000067'
  tag gtitle: 'LanMan Authentication Level'
  tag fix_id: 'F-41186r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
