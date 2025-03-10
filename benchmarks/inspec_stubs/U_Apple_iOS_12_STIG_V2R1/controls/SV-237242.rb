control 'SV-237242' do
  title 'Apple iOS must not include applications with the following characteristics: Siri when the device is locked.'
  desc "On Apple iOS devices, users can access the device's contact database or calendar to obtain phone numbers and other information using a human voice even when the mobile device is locked. Often this information is Personally Identifiable Information (PII), which is considered sensitive. It could also be used by an adversary to profile the user or engage in social engineering to obtain further information from other unsuspecting users. Disabling access to the contact database and calendar in these situations mitigates the risk of this attack. The AO may waive this requirement with written notice if the operational environment requires this capability.

SFR ID: FMT_SMF_EXT.1.1 #8b"
  desc 'check', 'Review configuration settings to confirm that Siri is disabled on the Lock screen.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow Siri while device is locked" is unchecked.

Alternatively, verify the text "<key>allowAssistantWhileLocked</key><false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Siri while locked not allowed" is listed.

If "Allow Siri while device is locked" is checked in the Apple iOS management tool, "<key>allowAssistantWhileLocked</key><true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Siri while locked not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Siri while the device is locked.'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-40461r642276_chk'
  tag severity: 'medium'
  tag gid: 'V-237242'
  tag rid: 'SV-237242r642278_rule'
  tag stig_id: 'AIOS-12-001300'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-40424r642277_fix'
  tag 'documentable'
  tag legacy: ['SV-96481', 'V-81767']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
