control 'SV-36025' do
  title 'Anonymous enumeration of SAM accounts will not be allowed.'
  desc 'This is a Category 1 finding as it allows anonymous logon users (null session connections) to list all account names, thus providing a list of potential points to attack the system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “Network access: Do not allow anonymous enumeration of SAM accounts” is not set to “Enabled”, then this is a finding. 


The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy values for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Do not allow anonymous enumeration of SAM accounts” to “Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-33725r1_chk'
  tag severity: 'high'
  tag gid: 'V-26283'
  tag rid: 'SV-36025r1_rule'
  tag gtitle: 'Restrict Anonymous SAM Enumeration'
  tag fix_id: 'F-29359r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
