control 'SV-258662' do
  title 'Samsung Android must be configured to disable ad hoc wireless client-to-client connection capability.'
  desc 'Ad hoc wireless client-to-client connections allow mobile devices to communicate with each other directly, circumventing network security policies and making the traffic invisible. This could allow the exposure of sensitive DOD data and increase the risk of downloading and installing malware on the DOD mobile device.

SFR ID: FMT_SMF_EXT.1.1/WLAN'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disallowing Wi-Fi Direct.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the user restrictions, verify "Wi-Fi Direct" has been set to "Disallow".

On the Samsung Android device:
1. Open Settings >> Connections >> Wi-Fi.
2. From the hamburger menu, select Wi-Fi Direct.
3. Verify no available devices are listed.

If on the management tool "Wi-Fi Direct" is not set to "Disallow", or on the Samsung Android device a Wi-Fi direct device is listed that can be connected to, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disallow Wi-Fi Direct.

On the management tool, in the user restrictions, set "Wi-Fi Direct" to "Disallow".

Wi-Fi direct connections and pairing between devices will become unavailable.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62402r931184_chk'
  tag severity: 'medium'
  tag gid: 'V-258662'
  tag rid: 'SV-258662r931186_rule'
  tag stig_id: 'KNOX-14-140110'
  tag gtitle: 'PP-MDF-333330'
  tag fix_id: 'F-62311r931185_fix'
  tag 'documentable'
  tag cci: ['CCI-002536']
  tag nist: ['SC-40']
end
