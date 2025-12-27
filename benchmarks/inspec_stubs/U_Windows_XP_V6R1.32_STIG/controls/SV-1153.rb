control 'SV-1153' do
  title 'The Send download LanMan compatible password option is not set to Send NTLMv2 response only\\refuse LM.'
  desc 'The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts.  NTLM is retained in later Windows versions  for compatibility with clients and servers that are running earlier versions of Windows.  It is also used to authenticate logons to stand-alone computers that are running later versions.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network security: LAN Manager authentication level” is not set to at least “Send NTLMv2 response only\\refuse LM” (Level 4), then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  LmCompatibilityLevel

Value Type:  REG_DWORD
Value:  4 (5 is also acceptable)
 
Documentable Explanation:  In a mixed Windows environment, if this setting needs to be loosened due to compatibility issues, then the reasons need to be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: LAN Manager authentication level” to at least “Send NTLMv2 response only\\refuse LM”.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-86r1_chk'
  tag severity: 'high'
  tag gid: 'V-1153'
  tag rid: 'SV-1153r1_rule'
  tag gtitle: 'LanMan Authentication Level'
  tag fix_id: 'F-91r1_fix'
  tag potential_impacts: 'Setting this to the required setting may prevent authentication with older Operating Systems and break some applications.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'IAIA-1, IAIA-2'
end
