control 'SV-254608' do
  title 'Apple iOS/iPadOS 16 must implement the management setting: Not allow automatic completion of Safari browser passcodes.'
  desc "The AutoFill functionality in the Safari web browser allows the user to complete a form that contains sensitive information, such as PII, without previous knowledge of the information. By allowing the use of the AutoFill functionality, an adversary who learns a user's iPhone or iPad passcode, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the AutoFill feature to provide information unknown to the adversary. By disabling the AutoFill functionality, the risk of an adversary gaining additional information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Enable autofill" is unchecked.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the Apple iOS/iPadOS management tool, verify "Enable autofill" is unchecked.

Alternatively, verify the text "<key>safariAllowAutoFill</key><false>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Restrictions".
6. Verify "Auto-fill in Safari not allowed" is present.

If "Enable autofill" is checked in the Apple iOS/iPadOS management tool, "<key>safariAllowAutoFill</key><true>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Auto-fill in Safari not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the AutoFill capability in the Safari app.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58219r862078_chk'
  tag severity: 'low'
  tag gid: 'V-254608'
  tag rid: 'SV-254608r862194_rule'
  tag stig_id: 'AIOS-16-010600'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58165r862079_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
