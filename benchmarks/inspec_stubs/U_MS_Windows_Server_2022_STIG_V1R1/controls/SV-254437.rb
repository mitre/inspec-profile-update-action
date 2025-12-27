control 'SV-254437' do
  title 'Windows Server 2022 Deny log on as a service user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied logon as a service.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a denial of service.'
  desc 'check', 'This applies to member servers and standalone or nondomain-joined systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a service" user right on domain-joined systems, this is a finding:

- Enterprise Admins Group
- Domain Admins Group

If any accounts or groups are defined for the "Deny log on as a service" user right on nondomain-joined systems, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyServiceLogonRight" user right on domain-joined systems, this is a finding:

S-1-5-root domain-519 (Enterprise Admins)
S-1-5-domain-512 (Domain Admins)

If any SIDs are defined for the user right on nondomain-joined systems, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> Deny log on as a service to include the following:

Domain systems:
- Enterprise Admins Group
- Domain Admins Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57922r849125_chk'
  tag severity: 'medium'
  tag gid: 'V-254437'
  tag rid: 'SV-254437r849127_rule'
  tag stig_id: 'WN22-MS-000100'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-57873r849126_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
