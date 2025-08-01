control 'SV-250967' do
  title 'Apple iOS/iPadOS 15 must implement the management setting: disable AirDrop.'
  desc "AirDrop is a way to send contact information or photos to other users with this same feature enabled. This feature enables a possible attack vector for adversaries to exploit. Once the attacker has gained access to the information broadcast by this feature, the attacker may distribute this sensitive information very quickly and without DoD's control or awareness. By disabling this feature, the risk of mass data exfiltration will be mitigated. 

Note: If the site uses Apple's optional Device Enrollment Program (DEP), this control is available as a supervised MDM control.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Determine if the site Authorizing Official (AO) has approved the use of AirDrop for unmanaged data transfer. Look for a document showing approval. If AirDrop is not approved, review configuration settings to confirm it is disabled. If approved, this requirement is not applicable.

This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding (if the AO has not approved the use of AirDrop for unmanaged data transfer).

If the iPhone or iPad being reviewed is supervised by the MDM, follow these procedures:

This check procedure is performed on both the device management tool and the iPhone and iPad device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS/iPadOS management tool, verify "Allow AirDrop" is unchecked.

On the iPhone/iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "AirDrop not allowed" is listed.

If the AO has not approved AirDrop and "AirDrop not allowed" is not listed in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of AirDrop for unmanaged data transfer, install a configuration profile to disable the AllowAirDrop control in the management tool. This a supervised-only control.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54402r801990_chk'
  tag severity: 'low'
  tag gid: 'V-250967'
  tag rid: 'SV-250967r801992_rule'
  tag stig_id: 'AIOS-15-012500'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54356r801991_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
