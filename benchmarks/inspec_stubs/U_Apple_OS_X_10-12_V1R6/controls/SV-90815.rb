control 'SV-90815' do
  title 'The OS X system must be configured with the prompt for Apple ID and iCloud disabled.'
  desc 'The prompt for Apple ID and iCloud must be disabled, as it might mislead new users into creating unwanted Apple IDs and iCloud storage accounts upon their first logon.'
  desc 'check', 'To check if the prompt for "Apple ID" and "iCloud" are disabled for new users, run the following command:

/usr/bin/sudo /usr/bin/defaults read /System/Library/User\\ Template/English.lproj/Library/Preferences/com.apple.SetupAssistant

If there is no result, if it prints out that the domain "does not exist", or the results do not include "DidSeeCloudSetup = 1 AND LastSeenCloudProductVersion = 10.12", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Disable iCloud Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76127'
  tag rid: 'SV-90815r1_rule'
  tag stig_id: 'AOSX-12-001125'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82765r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
