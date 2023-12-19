control 'SV-219387' do
  title 'Apple iOS/iPadOS must implement the management setting: disable AirDrop.'
  desc "An Airdrop feature is a way to send contact information or photos to other users with this same feature enabled. This feature enables a possible attack vector for adversaries to exploit. Once the attacker has gained access to the information broadcast by this feature, he/she may distribute this sensitive information very quickly and without DoD's control or awareness. By disabling this feature, the risk of mass data exfiltration will be mitigated.

Note: If the site uses Apple's optional Device Enrollment Program (DEP), this control is available as a supervised MDM control.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Determine if the site AO has approved the use of AirDrop for unmanaged data transfer. Look for a document showing approval. Review configuration settings to confirm AirDrop is disabled, if not approved. If approved, this requirement is not applicable.

This a Supervised-only control. If the iPhone or iPad being reviewed is not Supervised by the MDM, this control is automatically a finding (if the AO has not approved the use of Apple Watch for unmanaged data transfer).

If the iPhone or iPad being reviewed is Supervised by the MDM, follow these procedures:

This check procedure is performed on both the device management tool and the iPhone and iPad device.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS/iPadOS management tool, verify "Allow AirDrop" is unchecked.

On the iPhone/iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "AirDrop not allowed" is listed.

If the AO has not approved AirDrop and "AirDrop not allowed" is not listed in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of AirDrop for unmanaged data transfer, install a configuration profile to disable the AllowAirDrop control in the management tool. This a Supervised-only control.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21112r547672_chk'
  tag severity: 'low'
  tag gid: 'V-219387'
  tag rid: 'SV-219387r604137_rule'
  tag stig_id: 'AIOS-13-013000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21111r547673_fix'
  tag 'documentable'
  tag legacy: ['SV-106607', 'V-97503']
  tag cci: ['CCI-000097', 'CCI-000370', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 (1)', 'CM-6 b']
end
