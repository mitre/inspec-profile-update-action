control 'SV-48415' do
  title 'Unauthorized accounts must not have the Debug programs user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Debug Programs" user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components.  This right is given to Administrators in the default configuration.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment. 

If any accounts or groups other than the following are granted the "Debug Programs" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Debug Programs" to only include the following accounts or groups:

Administrators'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45084r2_chk'
  tag severity: 'high'
  tag gid: 'V-18010'
  tag rid: 'SV-48415r1_rule'
  tag stig_id: 'WN08-UR-000016'
  tag gtitle: 'User Right - Debug Programs'
  tag fix_id: 'F-41546r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
