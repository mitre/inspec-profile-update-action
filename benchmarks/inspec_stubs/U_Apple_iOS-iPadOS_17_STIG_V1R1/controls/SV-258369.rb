control 'SV-258369' do
  title 'The Apple iOS must be configured to disable automatic transfer of diagnostic data to an external device other than an MDM service with which the device has enrolled.'
  desc 'Many software systems automatically send diagnostic data to the manufacturer or a third party. This data enables the developers to understand real-world field behavior and improve the product based on that information. Unfortunately, it can also reveal information about what DOD users are doing with the systems and what causes them to fail. An adversary embedded within the software development team or elsewhere could use the information acquired to breach mobile operating system security. Disabling automatic transfer of such information mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47a'
  desc 'check', 'Review configuration settings to confirm "Allow sending diagnostic and usage data to Apple" is disabled.

This check procedure is performed on both the iOS management tool and the iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS management tool, verify "Allow sending diagnostic and usage data to Apple" is unchecked.

Alternatively, verify the text "<key>allowDiagnosticSubmission</key><false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Restrictions".
6. Verify "Diagnostic submission not allowed".

Note: This setting also disables "Share With App Developers".

If "Allow sending diagnostic and usage data to Apple" is checked in the iOS management tool, "<key>allowDiagnosticSubmission</key><true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Diagnostic submission not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable sending diagnostic data to an organization other than DOD.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62110r927788_chk'
  tag severity: 'low'
  tag gid: 'V-258369'
  tag rid: 'SV-258369r927790_rule'
  tag stig_id: 'AIOS-17-013400'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62034r927789_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
