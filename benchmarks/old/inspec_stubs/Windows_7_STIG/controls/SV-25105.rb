control 'SV-25105' do
  title 'The Lan Manager authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.'
  desc 'The Kerberos v5 authentication protocol is the default for authentication for domains.  NTLM which is less secure, is retained in later Windows versions for compatibility with standalone systems as well as applications that may still use it.  Earlier versions of the LM/NTLM protocol are particularly vulnerable to attack and must be prevented.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Network security: LAN Manager authentication level" is not set to "Send NTLMv2 response only\\refuse LM & NTLM" (Level 5), this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name:  LmCompatibilityLevel

Value Type:  REG_DWORD
Value:  5'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: LAN Manager authentication level" to "Send NTLMv2 response only\\refuse LM & NTLM".'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62063r2_chk'
  tag severity: 'high'
  tag gid: 'V-1153'
  tag rid: 'SV-25105r2_rule'
  tag gtitle: 'LanMan Authentication Level'
  tag fix_id: 'F-66961r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
