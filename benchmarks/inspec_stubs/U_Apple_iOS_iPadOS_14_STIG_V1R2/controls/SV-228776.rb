control 'SV-228776' do
  title 'Apple iOS/iPadOS must disable Find My Friends in the Find My app.'
  desc "This control does not share a DoD user's location, but encourages location sharing between DoD mobile device users, which can lead to OPSEC risks. Sharing the location of a DoD mobile device is a violation of AIOS-13-011900.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Find My Friends" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS/iPadOS management tool, verify "Find My Friends"  and "Allow modifying Find My Friends" are unchecked.

On the iPhone/iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Find My Friends" is not listed.

If "Find My Friends" and "Allow modifying Find My Friends" are not disabled in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "Find My Friends"  in the Find My app and "Allow modifying Find My Friends" in the management tool. This a supervised-only control.'
  impact 0.3
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-31011r569171_chk'
  tag severity: 'low'
  tag gid: 'V-228776'
  tag rid: 'SV-228776r561031_rule'
  tag stig_id: 'AIOS-14-011500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30988r569172_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000370', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 (1)', 'CM-6 b']
end
