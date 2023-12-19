control 'SV-225556' do
  title 'The Debug programs user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Debug programs" user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components.  This right is given to Administrators in the default configuration.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Debug programs" user right, this is a finding:

Administrators

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Debug programs" to only include the following accounts or groups:

Administrators'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27255r472010_chk'
  tag severity: 'high'
  tag gid: 'V-225556'
  tag rid: 'SV-225556r569185_rule'
  tag stig_id: 'WN12-UR-000016'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27243r472011_fix'
  tag 'documentable'
  tag legacy: ['SV-52115', 'V-18010']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
