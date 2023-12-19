control 'SV-32300' do
  title 'The LanMan authentication level will be set to Send NTLMv2 response only\\refuse LM & NTLM.'
  desc 'The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts.

The Windows NTLM protocol is retained in later Windows versions  for compatibility with clients and servers that are running earlier versions.  It is also used to authenticate logons to stand-alone computers that are running later versions.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options. 

If the value for “Network security: LAN Manager authentication level” is not set to “Send NTLMv2 response only\\refuse LM & NTLM” (Level 5), then this is a finding.

The policy referenced configures the following registry value:

Registry Path:  HKLM\\System\\CurrentControlSet\\Control\\Lsa\\
Value Name:	 LmCompatibilityLevel
Value Type:	REG_DWORD
Value:  5

Documentable Explanation: In a mixed Windows environment, if this setting needs to be loosened due to compatibility issues, then the reasons need to be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: LAN Manager authentication level” to “Send NTLMv2 response only\\refuse LM & NTLM”.'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32723r1_chk'
  tag severity: 'high'
  tag gid: 'V-1153'
  tag rid: 'SV-32300r1_rule'
  tag gtitle: 'LanMan Authentication Level'
  tag fix_id: 'F-28810r1_fix'
  tag potential_impacts: 'Setting this to the required setting may prevent authentication with older operating systems and break some applications.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
