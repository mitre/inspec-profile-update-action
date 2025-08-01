control 'SV-32339' do
  title 'The system will be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc 'This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.  The LAN Manager hash is a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network security: Do not store LAN Manager hash value on next password change” is not set to “Enabled”, then this is a finding.
 
The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  NoLMHash

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: Do not store LAN Manager hash value on next password change” to “Enabled”.'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32745r1_chk'
  tag severity: 'high'
  tag gid: 'V-3379'
  tag rid: 'SV-32339r1_rule'
  tag gtitle: 'LAN Manager Hash stored'
  tag fix_id: 'F-28824r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
