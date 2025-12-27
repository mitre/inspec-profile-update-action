control 'SV-205668' do
  title 'Windows Server 2019 Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a batch job" user right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.

The Guests group must be assigned to prevent unauthenticated access.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a batch job" user right, this is a finding:

- Guests Group

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If the following SID(s) are not defined for the "SeDenyBatchLogonRight" user right, this is a finding:

S-1-5-32-546 (Guests)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on as a batch job" to include the following:

- Guests Group'
  impact 0.5
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-5933r354922_chk'
  tag severity: 'medium'
  tag gid: 'V-205668'
  tag rid: 'SV-205668r569188_rule'
  tag stig_id: 'WN19-DC-000380'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-5933r354923_fix'
  tag 'documentable'
  tag legacy: ['SV-103089', 'V-93001']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
