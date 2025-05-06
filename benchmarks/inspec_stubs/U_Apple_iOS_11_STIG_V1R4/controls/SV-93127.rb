control 'SV-93127' do
  title 'Apple iOS device must have the latest available iOS operating system installed.'
  desc 'Required security features are not available in earlier OS versions. In addition, there may be known vulnerabilities in earlier versions.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm the most recently released version of iOS is installed.

This validation procedure is performed on both the Apple iOS management tool and the Apple iOS device. Go to http://www.apple.com and determine the most current version of iOS released by Apple.

In the MDM management console, review the version of iOS installed on a sample of managed devices. This procedure will vary depending on the MDM product.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "About" and view the installed version of iOS. Also, tap "Software Update" and verify the following message is shown on the screen: "Your software is up to date."

If the installed version of iOS on any reviewed iOS devices is not the latest released by Apple, this is a finding.'
  desc 'fix', 'Install the latest release version of Apple iOS on all managed iOS devices.'
  impact 0.7
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77983r1_chk'
  tag severity: 'high'
  tag gid: 'V-78421'
  tag rid: 'SV-93127r1_rule'
  tag stig_id: 'AIOS-11-011800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
