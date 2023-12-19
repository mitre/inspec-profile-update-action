control 'SV-219393' do
  title 'Apple iOS/iPadOS must disable Find My Friends in the Find My app.'
  desc "This control does not share a DoD user's location but encourages location sharing between DoD mobile device users, which can lead to OPSEC risks. Sharing the location of a DoD mobile device is a violation of AIOS-13-011900. 

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'This a Supervised-only control. If the iPhone or iPad being reviewed is not Supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is Supervised by the MDM, review configuration settings to confirm "Find My Friends" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS/iPadOS management tool, verify "Find My Friends" is unchecked.

On the iPhone/iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Find My Friends" is not listed.

If "Find My Friends" is not disabled in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Find My Friends in the Find My app in the management tool. This a Supervised-only control.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21118r547690_chk'
  tag severity: 'low'
  tag gid: 'V-219393'
  tag rid: 'SV-219393r604137_rule'
  tag stig_id: 'AIOS-13-013600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21117r547691_fix'
  tag 'documentable'
  tag legacy: ['SV-106619', 'V-97515']
  tag cci: ['CCI-000097', 'CCI-000366', 'CCI-000370']
  tag nist: ['AC-20 (2)', 'CM-6 b', 'CM-6 (1)']
end
