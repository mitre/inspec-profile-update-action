control 'SV-48508' do
  title 'Anonymous enumeration of SAM accounts must not be allowed.'
  desc 'Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "Network access: Do not allow anonymous enumeration of SAM accounts" is not set to "Enabled", this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45159r2_chk'
  tag severity: 'high'
  tag gid: 'V-26283'
  tag rid: 'SV-48508r2_rule'
  tag stig_id: 'WN08-SO-000051'
  tag gtitle: 'Restrict Anonymous SAM Enumeration'
  tag fix_id: 'F-41632r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
