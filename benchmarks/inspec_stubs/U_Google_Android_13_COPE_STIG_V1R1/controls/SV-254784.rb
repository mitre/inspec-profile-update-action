control 'SV-254784' do
  title 'Google Android 13 must be configured to disable ad hoc wireless client-to-client connection capability.'
  desc 'Ad hoc wireless client-to-client connections allow mobile devices to communicate with each other directly, circumventing network security policies and making the traffic invisible. This could allow the exposure of sensitive DOD data and increase the risk of downloading and installing malware of the DOD mobile device.

SFR ID: FMT_SMF_EXT.1.1/WLAN'
  desc 'check', 'Review the managed Google Android 13 device configuration settings to determine if the mobile device is configured to disable ad hoc wireless client-to-client connection capability.

This validation procedure is performed on both the MDM Administration console and the managed Google Android 13 device. 

On the MDM console: 

COBO:

1. Open "Settings Management".
2. Verify "Set location" is toggled to "OFF".

COPE:

1. Open "User restrictions on parent".
2. Verify "Disallow config location" is toggled to "ON".
3. Verify "Disallow share location" is toggled to "ON".

On the managed Google Android 13 device: 

COBO and COPE:

1. Go to Settings >> Network & Internet >> Network preferences.
2. Verify "Wi-Fi Direct" is greyed out and unavailable.

If the EMM console device policy is not set to disable Location sharing and configuration, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to disable ad hoc wireless client-to-client connection capability.

On the MDM console: 

COBO:

1. Open "Settings Management".
2. Toggle "Set location" to "OFF".

COPE:

1. Open "User restrictions on parent".
2. Toggle "Disallow config location" to "ON".
3. Toggle "Disallow share location" to "ON".

Note: Ad hoc and Wi-Fi Direct requires Location services to function; therefore, disabling this setting will disable the ad hoc and Wi-Fi Direct feature.'
  impact 0.5
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58395r862732_chk'
  tag severity: 'medium'
  tag gid: 'V-254784'
  tag rid: 'SV-254784r862734_rule'
  tag stig_id: 'GOOG-13-009500'
  tag gtitle: 'PP-MDF-323330'
  tag fix_id: 'F-58341r862733_fix'
  tag 'documentable'
  tag cci: ['CCI-002536']
  tag nist: ['SC-40']
end
