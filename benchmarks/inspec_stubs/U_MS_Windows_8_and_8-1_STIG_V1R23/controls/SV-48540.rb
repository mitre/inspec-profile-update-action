control 'SV-48540' do
  title 'Unauthorized accounts must not have the Lock pages in memory user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Lock pages in memory" user right allows physical memory to be assigned to processes, which could cause performance issues or a DoS.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Lock pages in memory" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Lock pages in memory" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45190r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26494'
  tag rid: 'SV-48540r2_rule'
  tag stig_id: 'WN08-UR-000029'
  tag gtitle: 'Lock pages in memory'
  tag fix_id: 'F-41662r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
