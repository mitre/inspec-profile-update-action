control 'SV-48534' do
  title 'Unauthorized accounts must not have the Force shutdown from a remote system user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Force shutdown from a remote system" user right can remotely shut down a system which could result in a DoS.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Force shutdown from a remote system" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Force shutdown from a remote system" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45184r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26488'
  tag rid: 'SV-48534r2_rule'
  tag stig_id: 'WN08-UR-000023'
  tag gtitle: 'Force shutdown from a remote system'
  tag fix_id: 'F-41656r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
