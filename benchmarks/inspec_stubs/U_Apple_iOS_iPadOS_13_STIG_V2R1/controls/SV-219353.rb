control 'SV-219353' do
  title 'Apple iOS/iPadOS must not include applications with the following characteristics: Voice dialing application if available when MD is locked.'
  desc "On iPhone and iPads, users can access the device's contact database or calendar to obtain phone numbers and other information using a human voice even when the mobile device is locked. Often this information is Personally Identifiable Information (PII), which is considered sensitive. It could also be used by an adversary to profile the user or engage in social engineering to obtain further information from other unsuspecting users. Disabling access to the contact database and calendar in these situations mitigates the risk of this attack.

SFR ID: FMT_SMF_EXT.1.1 #8b"
  desc 'check', 'Review configuration settings to confirm that "Allow Voice Dialing when locked" is disabled on the Lock screen.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow voice dialing while device locked" is unchecked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Voice dialing while locked not allowed" is listed.

If "Allow voice dialing when locked not allowed" is checked in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad does not list "Voice dialing while locked not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Voice Control while the device is locked.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21078r547576_chk'
  tag severity: 'medium'
  tag gid: 'V-219353'
  tag rid: 'SV-219353r604137_rule'
  tag stig_id: 'AIOS-13-001400'
  tag gtitle: 'PP-MDF-301100'
  tag fix_id: 'F-21077r547577_fix'
  tag 'documentable'
  tag legacy: ['SV-106537', 'V-97433']
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
