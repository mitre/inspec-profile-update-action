control 'SV-225083' do
  title 'The Increase scheduling priority user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Increase scheduling priority" user right can change a scheduling priority, causing performance issues or a denial of service.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Increase scheduling priority" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeIncreaseBasePriorityPrivilege" user right, this is a finding.

S-1-5-32-544 (Administrators)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN16-00-000060) and required frequency of changes (WN16-00-000070).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Increase scheduling priority" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26774r466150_chk'
  tag severity: 'medium'
  tag gid: 'V-225083'
  tag rid: 'SV-225083r877392_rule'
  tag stig_id: 'WN16-UR-000230'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26762r466151_fix'
  tag 'documentable'
  tag legacy: ['SV-88451', 'V-73787']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
