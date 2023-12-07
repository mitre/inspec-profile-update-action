control 'SV-225002' do
  title 'The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied logon as a service.

Incorrect configurations could prevent services from starting and result in a denial of service.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are defined for the "Deny log on as a service" user right, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs are granted the "SeDenyServiceLogonRight" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on as a service" to include no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26693r465908_chk'
  tag severity: 'medium'
  tag gid: 'V-225002'
  tag rid: 'SV-225002r569186_rule'
  tag stig_id: 'WN16-DC-000390'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-26681r465909_fix'
  tag 'documentable'
  tag legacy: ['SV-88429', 'V-73765']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
