control 'SV-88421' do
  title 'The Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny access to this computer from the network" user right defines the accounts that are prevented from logging on from the network.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" user right, this is a finding.

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SIDs are not defined for the "SeDenyNetworkLogonRight" user right, this is a finding.

S-1-5-32-546 (Guests)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny access to this computer from the network" to include the following:

- Guests Group'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-91489r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73757'
  tag rid: 'SV-88421r2_rule'
  tag stig_id: 'WN16-DC-000370'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-80207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
