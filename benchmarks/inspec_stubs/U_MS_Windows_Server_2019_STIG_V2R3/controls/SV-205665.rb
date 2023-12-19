control 'SV-205665' do
  title 'Windows Server 2019 Access this computer from the network user right must only be assigned to the Administrators, Authenticated Users, and 
Enterprise Domain Controllers groups on domain controllers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access this computer from the network" right may access resources on the system, and this right must be limited to those requiring it.'
  desc 'check', 'This applies to domain controllers. It is NA for other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" right, this is a finding.

- Administrators
- Authenticated Users
- Enterprise Domain Controllers

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeNetworkLogonRight" user right, this is a finding.

S-1-5-32-544 (Administrators)
S-1-5-11 (Authenticated Users)
S-1-5-9 (Enterprise Domain Controllers)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN19-00-000050) and required frequency of changes (WN19-00-000060).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access this computer from the network" to include only the following accounts or groups:

- Administrators
- Authenticated Users
- Enterprise Domain Controllers'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-5930r354913_chk'
  tag severity: 'medium'
  tag gid: 'V-205665'
  tag rid: 'SV-205665r569188_rule'
  tag stig_id: 'WN19-DC-000340'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-5930r354914_fix'
  tag 'documentable'
  tag legacy: ['SV-103083', 'V-92995']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
