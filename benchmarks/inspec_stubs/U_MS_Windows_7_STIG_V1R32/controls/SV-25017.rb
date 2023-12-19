control 'SV-25017' do
  title 'The Act as part of the operating system user right must be granted to no accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Act as part of the operating system" user right can assume the identity of any user and gain access to resources that user is authorized to access.  Any accounts with this right can take complete control of a system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups (to include administrators), are granted the "Act as part of the operating system" right, this is a finding.
 
Documentable Explanation:  Some applications require this right to function. Any exception needs to be documented with the ISSO.  Passwords for accounts with this user right must be protected as highly privileged accounts.  Acceptable forms of documentation include vendor published documents and application owner confirmation.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Act as part of the operating system" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60769r2_chk'
  tag severity: 'high'
  tag gid: 'V-1102'
  tag rid: 'SV-25017r2_rule'
  tag stig_id: 'WINUR-000003'
  tag gtitle: 'User Right - Act as part of OS'
  tag fix_id: 'F-65501r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
