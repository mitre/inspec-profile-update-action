control 'SV-225014' do
  title 'The "Access this computer from the network" user right must only be assigned to the Administrators and Authenticated Users groups on member servers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access this computer from the network" user right may access resources on the system, and this right must be limited to those requiring it.'
  desc 'check', 'This applies to member servers and standalone or nondomain-joined systems. A separate version applies to domain controllers.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" user right, this is a finding.

- Administrators
- Authenticated Users

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeNetworkLogonRight" user right, this is a finding.

S-1-5-32-544 (Administrators)
S-1-5-11 (Authenticated Users)

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN16-00-000060) and required frequency of changes (WN16-00-000070).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access this computer from the network" to include only the following accounts or groups:

- Administrators
- Authenticated Users'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26705r857271_chk'
  tag severity: 'medium'
  tag gid: 'V-225014'
  tag rid: 'SV-225014r857272_rule'
  tag stig_id: 'WN16-MS-000340'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-26693r465945_fix'
  tag 'documentable'
  tag legacy: ['SV-88397', 'V-73733']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
