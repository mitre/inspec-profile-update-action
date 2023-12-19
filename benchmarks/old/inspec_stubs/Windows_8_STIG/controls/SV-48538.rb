control 'SV-48538' do
  title 'Unauthorized accounts must not have the Increase scheduling priority user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Increase scheduling priority" user right can change a scheduling priority causing performance issues or a DoS.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Increase scheduling priority" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Increase scheduling priority" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45188r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26492'
  tag rid: 'SV-48538r2_rule'
  tag stig_id: 'WN08-UR-000027'
  tag gtitle: 'Increase scheduling priority'
  tag fix_id: 'F-41660r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
