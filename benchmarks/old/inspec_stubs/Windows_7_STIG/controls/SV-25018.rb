control 'SV-25018' do
  title 'Unauthorized accounts must not have the Debug programs user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Debug Programs" user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups are granted the “Debug programs” right, this is a finding.

If Administrators require this right for troubleshooting or application issues, it should be assigned on a 
temporary basis as needed.

Documentable Explanation: Some applications may require this right to function. Any exception needs to be documented with the ISSO. Acceptable forms of documentation include vendor published documents and application owner confirmation.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Debug Programs" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60805r2_chk'
  tag severity: 'high'
  tag gid: 'V-18010'
  tag rid: 'SV-25018r2_rule'
  tag stig_id: 'WINUR-000016'
  tag gtitle: 'User Right - Debug Programs'
  tag fix_id: 'F-65537r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
