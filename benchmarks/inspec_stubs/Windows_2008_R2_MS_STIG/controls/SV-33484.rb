control 'SV-33484' do
  title 'Unauthorized accounts must not have the Manage auditing and security log user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Manage auditing and security log" user right can manage the security log and change auditing configurations.  This could be used to clear evidence of tampering.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Manage auditing and security log" right, this is a finding:

Administrators

If the organization has an Auditors group, the assignment of this group to the user right would not be a finding.

If an application requires this user right, this would not be a finding.
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the ISSO.
The application account must meet requirements for application account passwords, such as length (V-36661) and required changes frequency (V-36662).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Manage auditing and security log" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-72729r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26496'
  tag rid: 'SV-33484r4_rule'
  tag stig_id: 'WINUR-000032'
  tag gtitle: 'Manage auditing and security log'
  tag fix_id: 'F-67169r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000171', 'CCI-001914']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 b', 'AU-12 (3)']
end
