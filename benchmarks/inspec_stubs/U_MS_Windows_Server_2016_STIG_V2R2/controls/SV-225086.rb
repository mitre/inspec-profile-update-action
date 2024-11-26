control 'SV-225086' do
  title 'The Manage auditing and security log user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Manage auditing and security log" user right can manage the security log and change auditing configurations. This could be used to clear evidence of tampering.

'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Manage auditing and security log" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeSecurityPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)

If the organization has an Auditors group, the assignment of this group to the user right would not be a finding.

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN16-00-000060) and required frequency of changes (WN16-00-000070).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Manage auditing and security log" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26777r466159_chk'
  tag severity: 'medium'
  tag gid: 'V-225086'
  tag rid: 'SV-225086r569186_rule'
  tag stig_id: 'WN16-UR-000260'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-26765r466160_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000063-GPOS-00032', 'SRG-OS-000337-GPOS-00129']
  tag 'documentable'
  tag legacy: ['SV-88457', 'V-73793']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000171', 'CCI-001914']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 b', 'AU-12 (3)']
end
