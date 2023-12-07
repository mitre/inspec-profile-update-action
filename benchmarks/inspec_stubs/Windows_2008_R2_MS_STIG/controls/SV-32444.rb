control 'SV-32444' do
  title 'Unauthorized accounts must not have the Debug programs user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Debug programs" user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Debug Programs" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Debug Programs" to only include the following accounts or groups:

Administrators'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-61339r2_chk'
  tag severity: 'high'
  tag gid: 'V-18010'
  tag rid: 'SV-32444r3_rule'
  tag stig_id: 'WINUR-000016'
  tag gtitle: 'User Right - Debug Programs'
  tag fix_id: 'F-43223r3_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If an application requires this user right, this can be downgraded to a CAT III if the following conditions are met:
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the ISSO.
Passwords for accounts with this user right must be protected as highly privileged accounts.
The application account must meet requirements for application account passwords, such as length and required changes frequency (V-14271).'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
