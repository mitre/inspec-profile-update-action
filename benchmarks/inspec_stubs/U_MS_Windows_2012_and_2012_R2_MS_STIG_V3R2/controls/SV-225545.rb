control 'SV-225545' do
  title 'The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access Credential Manager as a trusted caller" user right may be able to retrieve the credentials of other accounts from Credential Manager.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Access Credential Manager as a trusted caller" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access Credential Manager as a trusted caller" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27244r471977_chk'
  tag severity: 'medium'
  tag gid: 'V-225545'
  tag rid: 'SV-225545r569185_rule'
  tag stig_id: 'WN12-UR-000001'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27232r471978_fix'
  tag 'documentable'
  tag legacy: ['SV-53120', 'V-26469']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
