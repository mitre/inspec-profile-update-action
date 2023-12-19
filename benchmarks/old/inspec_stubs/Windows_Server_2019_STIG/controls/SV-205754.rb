control 'SV-205754' do
  title 'Windows Server 2019 Create global objects user right must only be assigned to Administrators, Service, Local Service, and Network Service.'
  desc %q(Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create global objects" user right can create objects that are available to all sessions, which could affect processes in other users' sessions.)
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create global objects" user right, this is a finding:

- Administrators
- Service
- Local Service
- Network Service

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeCreateGlobalPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)
S-1-5-6 (Service)
S-1-5-19 (Local Service)
S-1-5-20 (Network Service)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN19-00-000050) and required frequency of changes (WN19-00-000060).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create global objects" to include only the following accounts or groups:

- Administrators
- Service
- Local Service
- Network Service'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6019r355180_chk'
  tag severity: 'medium'
  tag gid: 'V-205754'
  tag rid: 'SV-205754r877392_rule'
  tag stig_id: 'WN19-UR-000070'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-6019r355181_fix'
  tag 'documentable'
  tag legacy: ['V-93059', 'SV-103147']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
