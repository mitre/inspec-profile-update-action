control 'SV-90817' do
  title 'The OS X system must be configured so that users do not have Apple IDs signed into iCloud.'
  desc 'Users should not sign into iCloud, as this leads to the possibility that sensitive data could be saved to iCloud storage or that users could inadvertently introduce viruses or malware previously saved to iCloud from other systems.'
  desc 'check', "To see if any user account has configured an Apple ID for iCloud usage, run the following command:

/usr/bin/sudo find /Users/ -name 'MobileMeAccounts.plist' -exec /usr/bin/defaults read '{}' \\;

If the results show any accounts listed, this is a finding."
  desc 'fix', 'This must be resolved manually.

With the affected user logged on, open System Preferences >> iCloud.

Choose "Sign Out".'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76129'
  tag rid: 'SV-90817r1_rule'
  tag stig_id: 'AOSX-12-001130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82767r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
