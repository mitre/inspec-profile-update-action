control 'SV-48029' do
  title 'No accounts must be granted the Act as part of the operating system user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Act as part of the operating system" user right can assume the identity of any user and gain access to resources that user is authorized to access.  Any accounts with this right can take complete control of a system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups (to include administrators), are granted the "Act as part of the operating system" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Act as part of the operating system" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44767r1_chk'
  tag severity: 'high'
  tag gid: 'V-1102'
  tag rid: 'SV-48029r1_rule'
  tag stig_id: 'WN08-UR-000003'
  tag gtitle: 'User Right - Act as part of OS'
  tag fix_id: 'F-41167r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
