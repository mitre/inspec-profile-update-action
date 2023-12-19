control 'SV-88449' do
  title 'The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf. An attacker could use this to elevate privileges.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Impersonate a client after authentication" user right, this is a finding.

- Administrators
- Service
- Local Service
- Network Service

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeImpersonatePrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)
S-1-5-6 (Service)
S-1-5-19 (Local Service)
S-1-5-20 (Network Service)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN16-00-000060) and required frequency of changes (WN16-00-000070).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Impersonate a client after authentication" to include only the following accounts or groups:

- Administrators
- Service
- Local Service
- Network Service'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-91517r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73785'
  tag rid: 'SV-88449r2_rule'
  tag stig_id: 'WN16-UR-000220'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-80235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
