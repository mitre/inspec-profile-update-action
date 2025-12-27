control 'SV-250955' do
  title 'iPhone and iPad must have the latest available iOS/iPadOS operating system installed.'
  desc 'Required security features are not available in earlier OS versions. In addition, earlier versions may have known vulnerabilities.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm the most recently released version of iOS is installed.

This validation procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. Go to https://www.apple.com and determine the most current version of iOS released by Apple.

In the MDM management console, review the version of iOS installed on a sample of managed devices. This procedure will vary depending on the MDM product.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "About" and view the installed version of iOS. 
4. Go back to the "General" screen. Tap "Software Update" and verify the following message is shown on the screen: "Your software is up to date."

If the installed version of iOS on any reviewed iOS/iPadOS devices is not the latest released by Apple, this is a finding.'
  desc 'fix', 'Install the latest release version of Apple iOS/iPadOS on all managed iOS devices.'
  impact 0.7
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54390r801954_chk'
  tag severity: 'high'
  tag gid: 'V-250955'
  tag rid: 'SV-250955r801956_rule'
  tag stig_id: 'AIOS-15-011200'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54344r801955_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
