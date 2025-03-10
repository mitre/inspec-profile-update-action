control 'SV-41844' do
  title 'The domain controller must be configured to allow reset of machine account passwords.'
  desc 'Enabling this setting on all domain controllers in a domain prevents domain members from changing their computer account passwords. If these passwords are weak or compromised, the inability to change them may leave these computers vulnerable.'
  desc 'check', '1. Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view.

2. Navigate to Local Policies and select Security Options.

3. If the value for “Domain Controller: Refuse machine account password changes” is set to  "Enabled", then this is a finding.'
  desc 'fix', 'Set the value for “Domain Controller: Refuse machine account password changes” to “Disabled”.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name:  RefusePasswordChange

Value Type:  REG_DWORD
Value:  0'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32084r1_chk'
  tag severity: 'low'
  tag gid: 'V-4408'
  tag rid: 'SV-41844r1_rule'
  tag stig_id: 'AD.3107_2008'
  tag gtitle: 'Computer Account Password Change'
  tag fix_id: 'F-28441r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
