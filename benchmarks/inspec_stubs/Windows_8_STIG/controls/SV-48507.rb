control 'SV-48507' do
  title 'Unauthorized accounts must not have the Take ownership of files or other objects user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Take ownership of files or other objects" user right can take ownership of objects and make changes.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Take ownership of files or other objects" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Take ownership of files or other objects" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26506'
  tag rid: 'SV-48507r2_rule'
  tag stig_id: 'WN08-UR-000042'
  tag gtitle: 'Take ownership of files or other objects'
  tag fix_id: 'F-41630r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
