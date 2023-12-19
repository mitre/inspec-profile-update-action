control 'SV-214905' do
  title 'The macOS system must be configured with the prompt for Apple ID and iCloud disabled.'
  desc 'The prompt for Apple ID and iCloud must be disabled, as it might mislead new users into creating unwanted Apple IDs and iCloud storage accounts upon their first logon.'
  desc 'check', 'To check if the system is configured to skip cloud setup, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipCloudSetup

If “SkipCloudSetup" is not set to "1", this is a finding.

To check if the prompt for "Apple ID" and "iCloud" are disabled for new users, run the following command:

/usr/bin/sudo /usr/bin/defaults read /System/Library/User\\ Template/English.lproj/Library/Preferences/com.apple.SetupAssistant

If there is no result, if it prints out that the domain "does not exist", or the results do not include "DidSeeCloudSetup = 1 AND LastSeenCloudProductVersion = 10.12", this is a finding.'
  desc 'fix', 'This setting is enforced using the “Login Window Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16105r397287_chk'
  tag severity: 'medium'
  tag gid: 'V-214905'
  tag rid: 'SV-214905r609363_rule'
  tag stig_id: 'AOSX-13-001125'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16103r397288_fix'
  tag 'documentable'
  tag legacy: ['SV-96403', 'V-81689']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
