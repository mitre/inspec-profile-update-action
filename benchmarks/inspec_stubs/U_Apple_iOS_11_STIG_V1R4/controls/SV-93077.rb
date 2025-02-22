control 'SV-93077' do
  title 'Apple iOS must not include applications with the following characteristics: Voice dialing application if available when MD is locked.'
  desc "On Apple iOS devices, users can access the device's contact database or calendar to obtain phone numbers and other information using a human voice even when the mobile device is locked. Often this information is Personally Identifiable Information (PII), which is considered sensitive. It could also be used by an adversary to profile the user or engage in social engineering to obtain further information from other unsuspecting users. Disabling access to the contact database and calendar in these situations mitigates the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #8b"
  desc 'check', 'Review configuration settings to confirm that "Allow Voice Dialing when locked" is disabled on the Lock screen.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow voice dialing while device locked" is unchecked.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Voice dialing while locked not allowed" is listed.

If "Allow voice dialing when locked not allowed" is checked in the Apple iOS management tool or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Voice dialing while locked not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Voice Control while the device is locked.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78371'
  tag rid: 'SV-93077r1_rule'
  tag stig_id: 'AIOS-11-001300'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-85103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
