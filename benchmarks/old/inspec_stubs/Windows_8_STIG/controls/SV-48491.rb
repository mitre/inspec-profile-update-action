control 'SV-48491' do
  title 'Unauthorized accounts must not have the Create permanent shared objects user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared objects.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Create permanent shared objects" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Create permanent shared objects" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45148r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26481'
  tag rid: 'SV-48491r2_rule'
  tag stig_id: 'WN08-UR-000014'
  tag gtitle: 'Create permanent shared objects'
  tag fix_id: 'F-41614r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
