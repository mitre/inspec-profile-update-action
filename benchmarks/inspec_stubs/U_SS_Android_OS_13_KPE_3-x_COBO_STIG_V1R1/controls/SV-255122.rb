control 'SV-255122' do
  title 'Samsung Android must be configured to enable authentication of personal hotspot connections to the device using a pre-shared key.'
  desc 'If no authentication is required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk.

Application note: If hotspot functionality is permitted, it must be authenticated via a preshared key. There is no requirement to enable hotspot functionality, and it is recommended this functionality be disabled by default.

SFR ID: FMT_SMF_EXT.1.1 #41'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enabling authentication of personal hotspot connections to the device using a preshared key. 

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify "Configure tethering" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Connections.
2. Verify "Mobile Hotspot and Tethering" is greyed out.

If on the management tool "Configure tethering" is not set to "Disallow", or on the Samsung Android device "Mobile Hotspot and Tethering" is not greyed out, this is a finding.'
  desc 'fix', %q(Configure the Samsung Android devices to enable authentication of personal hotspot connections to the device using a pre-shared key.

On the management tool, in the device restrictions, set "Configure tethering" to "Disallow".

If the deployment requires the use of Mobile Hotspot and Tethering, KPE policy can be used to allow its usage in a STIG-approved configuration. In this case, do not configure this policy, and instead replace with KPE policy (innately by the management tool or via KSP) "Allow open Wi-Fi connection" with value "Disable" and add Training Topic "Don't use Wi-Fi Sharing" (see supplemental document for additional information).)
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58735r867301_chk'
  tag severity: 'medium'
  tag gid: 'V-255122'
  tag rid: 'SV-255122r867303_rule'
  tag stig_id: 'KNOX-13-110160'
  tag gtitle: 'PP-MDF-323260'
  tag fix_id: 'F-58679r867302_fix'
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-002314']
  tag nist: ['AC-18 (1)', 'AC-17 (1)']
end
