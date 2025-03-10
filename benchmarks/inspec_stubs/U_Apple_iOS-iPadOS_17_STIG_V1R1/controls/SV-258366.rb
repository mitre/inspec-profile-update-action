control 'SV-258366' do
  title 'Apple iOS/iPadOS 17 must disable "Find My Friends" in the "Find My" app.'
  desc "This control does not share a DOD user's location but encourages location sharing between DOD mobile device users, which can lead to operational security (OPSEC) risks. Sharing the location of a DOD mobile device is a violation of AIOS-17-011700.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Find My Friends" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS/iPadOS management tool, verify "Allow Find My Friends" and "Allow modifying Find My Friends" are unchecked.

On the iPhone/iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Allow Find My Friends" is not listed and "Changing Find My Friends settings not allowed" is listed.

If "Allow Find My Friends" and "Allow modifying Find My Friends" are not disabled in the management tool and on the Apple device "Allow Find My Friends" is listed and "Changing Find My Friends settings not allowed" is not listed, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "Find My Friends" in the Find My app and "Allow modifying Find My Friends" in the management tool. This a supervised-only control.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62107r927779_chk'
  tag severity: 'low'
  tag gid: 'V-258366'
  tag rid: 'SV-258366r927781_rule'
  tag stig_id: 'AIOS-17-013100'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62031r927780_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
