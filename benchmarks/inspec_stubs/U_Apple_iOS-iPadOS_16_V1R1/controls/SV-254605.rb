control 'SV-254605' do
  title 'Apple iOS/iPadOS 16 must be configured to disable ad hoc wireless client-to-client connection capability.'
  desc 'Ad hoc wireless client-to-client connections allow mobile devices to communicate with each other directly, circumventing network security policies and making the traffic invisible. This could allow the exposure of sensitive DoD data and increase the risk of downloading and installing malware on the DoD mobile device.

SFR ID: FMT_SMF_EXT.1.1/WLAN'
  desc 'check', 'Determine if the site authorizing official (AO) has approved the use of AirDrop for unmanaged data transfer. Look for a document showing approval. If AirDrop is not approved, review configuration settings to confirm it is disabled. If AirDrop is approved, this requirement is not applicable.

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

If the AO has not approved AirDrop, and "AirDrop not allowed" is not listed in the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of AirDrop for unmanaged data transfer, install a configuration profile to disable the AllowAirDrop control in the management tool. This a supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58216r862069_chk'
  tag severity: 'medium'
  tag gid: 'V-254605'
  tag rid: 'SV-254605r862071_rule'
  tag stig_id: 'AIOS-16-010200'
  tag gtitle: 'PP-MDF-323330'
  tag fix_id: 'F-58162r862070_fix'
  tag 'documentable'
  tag cci: ['CCI-002536']
  tag nist: ['SC-40']
end
