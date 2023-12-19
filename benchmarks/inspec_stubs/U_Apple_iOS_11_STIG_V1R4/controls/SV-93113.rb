control 'SV-93113' do
  title 'Apple iOS must implement the management setting: not allow automatic completion of Safari browser passcodes.'
  desc "The AutoFill functionality in the Safari web browser allows the user to complete a form that contains sensitive information, such as PII, without previous knowledge of the information. By allowing the use of the AutoFill functionality, an adversary who learns a user's Apple iOS device passcode, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the AutoFill feature to provide information unknown to the adversary. By disabling the AutoFill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Enable autofill" is unchecked.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Enable autofill" is unchecked.

Alternatively, verify the text "<key>safariAllowAutoFill</key><false>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Verify "Auto-fill in Safari not allowed" is present.

If "Enable autofill" is checked in the Apple iOS management tool, or "<key>safariAllowAutoFill</key><true>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Auto-fill in Safari not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the AutoFill capability in the Safari app.'
  impact 0.3
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77969r1_chk'
  tag severity: 'low'
  tag gid: 'V-78407'
  tag rid: 'SV-93113r1_rule'
  tag stig_id: 'AIOS-11-011000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85139r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
