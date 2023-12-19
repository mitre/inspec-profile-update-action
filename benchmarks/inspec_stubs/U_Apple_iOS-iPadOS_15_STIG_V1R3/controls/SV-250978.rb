control 'SV-250978' do
  title 'Apple iOS/iPadOS 15 must disable "Allow network drive access in Files access".'
  desc 'Allowing network drive access by the Files app could lead to the introduction of malware or unauthorized software into the DoD IT infrastructure and compromise of sensitive DoD information and systems.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow network drive access in Files access" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Allow network drive access in Files access" is not listed.

If "Allow network drive access in Files access" is not disabled in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "Allow network drive access in Files access".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54413r802023_chk'
  tag severity: 'medium'
  tag gid: 'V-250978'
  tag rid: 'SV-250978r802025_rule'
  tag stig_id: 'AIOS-15-014300'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54367r802024_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
