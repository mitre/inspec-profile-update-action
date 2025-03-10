control 'SV-258359' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: disable AirDrop.'
  desc "AirDrop is a way to send contact information or photos to other users with this same feature enabled. This feature enables a possible attack vector for adversaries to exploit. Once the attacker has gained access to the information broadcast by this feature, the attacker may distribute this sensitive information very quickly and without DOD's control or awareness. By disabling this feature, the risk of mass data exfiltration will be mitigated. 

Note: If the site uses Apple's optional Automatic Device Enrollment, this control is available as a supervised MDM control.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Determine if the site authorizing official (AO) has approved the use of AirDrop for unmanaged data transfer. Look for a document showing approval. If AirDrop is not approved, review configuration settings to confirm it is disabled. If approved, this requirement is not applicable.

This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding (if the authorizing official [AO] has not approved the use of AirDrop for unmanaged data transfer).

If the iPhone or iPad being reviewed is supervised by the MDM, follow these procedures:

This check procedure is performed on both the device management tool and the iPhone and iPad device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the iOS/iPadOS management tool, verify "Allow AirDrop" is unchecked.

On the iPhone/iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management". 
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "AirDrop not allowed" or "Sharing managed documents using Airdrop not allowed" is listed.

If the AO has not approved AirDrop and "AirDrop not allowed" is not listed in the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of AirDrop for unmanaged data transfer, install a configuration profile to disable the "Allow AirDrop" control in the management tool. This a supervised-only control.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62100r927758_chk'
  tag severity: 'low'
  tag gid: 'V-258359'
  tag rid: 'SV-258359r927760_rule'
  tag stig_id: 'AIOS-17-012500'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62024r927759_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
