control 'SV-225079' do
  title 'The Debug programs user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Debug programs" user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components. This right is given to Administrators in the default configuration.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Debug programs" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeDebugPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN16-00-000060) and required frequency of changes (WN16-00-000070).

Passwords for application accounts with this user right must be protected as highly privileged accounts.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Debug programs" to include only the following accounts or groups:

- Administrators'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26770r466138_chk'
  tag severity: 'high'
  tag gid: 'V-225079'
  tag rid: 'SV-225079r852398_rule'
  tag stig_id: 'WN16-UR-000130'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26758r466139_fix'
  tag 'documentable'
  tag legacy: ['SV-88419', 'V-73755']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
