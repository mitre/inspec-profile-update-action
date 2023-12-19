control 'SV-103163' do
  title 'Windows Server 2019 Load and unload device drivers user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Load and unload device drivers" user right allows a user to load device drivers dynamically on a system. This could be used by an attacker to install malicious code.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Load and unload device drivers" user right, this is a finding:

- Administrators

For server core installations, run the following command:

Secedit /Export /Areas User_Rights /cfg c:\\path\\filename.txt

Review the text file.

If any SIDs other than the following are granted the "SeLoadDriverPrivilege" user right, this is a finding:

S-1-5-32-544 (Administrators)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Load and unload device drivers" to include only the following accounts or groups:

- Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92393r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93075'
  tag rid: 'SV-103163r1_rule'
  tag stig_id: 'WN19-UR-000150'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-99321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
