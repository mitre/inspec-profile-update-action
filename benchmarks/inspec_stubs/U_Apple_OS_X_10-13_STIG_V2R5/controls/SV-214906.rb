control 'SV-214906' do
  title 'The macOS system must be configured so that users do not have Apple IDs signed into iCloud.'
  desc 'Users should not sign into iCloud, as this leads to the possibility that sensitive data could be saved to iCloud storage or that users could inadvertently introduce viruses or malware previously saved to iCloud from other systems.'
  desc 'check', "To see if any user account has configured an Apple ID for iCloud usage, run the following command:

/usr/bin/sudo find /Users/ -name 'MobileMeAccounts.plist' -exec /usr/bin/defaults read '{}' \\;

If the results show any accounts listed, this is a finding."
  desc 'fix', 'This must be resolved manually.

With the affected user logged on, open System Preferences >> iCloud.

Choose "Sign Out".'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16106r397290_chk'
  tag severity: 'medium'
  tag gid: 'V-214906'
  tag rid: 'SV-214906r609363_rule'
  tag stig_id: 'AOSX-13-001130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16104r397291_fix'
  tag 'documentable'
  tag legacy: ['V-81691', 'SV-96405']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
