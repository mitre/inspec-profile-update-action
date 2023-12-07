control 'SV-224999' do
  title 'The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on through Remote Desktop Services" user right can access a system through Remote Desktop.'
  desc 'check', 'This applies to domain controllers, it is NA for other systems.

Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding.

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeRemoteInteractiveLogonRight" user right, this is a finding.

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on through Remote Desktop Services" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26690r465899_chk'
  tag severity: 'medium'
  tag gid: 'V-224999'
  tag rid: 'SV-224999r569186_rule'
  tag stig_id: 'WN16-DC-000360'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-26678r465900_fix'
  tag 'documentable'
  tag legacy: ['V-73741', 'SV-88405']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
