control 'SV-252420' do
  title 'Samsung Android must be configured to enable authentication of personal hotspot connections to the device using a pre-shared key.'
  desc 'If no authentication is required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk.

Application note: If hotspot functionality is permitted, it must be authenticated via a preshared key. There is no requirement to enable hotspot functionality, and it is recommended this functionality be disabled by default.

SFR ID: FMT_SMF_EXT.1.1 #41'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enabling authentication of personal hotspot connections to the device using a preshared key. 

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify "Config tethering" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Connections.
2. Verify that "Mobile Hotspot and Tethering" is greyed out.

If on the management tool "Config tethering" is not set to "Disallow", or on the Samsung Android device "Mobile Hotspot and Tethering" is not greyed out, this is a finding.'
  desc 'fix', %q(Configure the Samsung Android devices to enable authentication of personal hotspot connections to the device using a pre-shared key.

On the management tool, in the device restrictions, set "Config tethering" to "Disallow".

If your deployment requires the use of Mobile Hotspot & Tethering, KPE policy can be used to allow its usage in a STIG approved configuration. In this case, do not configure this policy, and instead replace with KPE policy (innately by management tool or via KSP) "Allow open Wi-Fi connection" with value "Disable" and add Training Topic "Don't use Wi-Fi Sharing" (see supplemental document for additional information))
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COPE'
  tag check_id: 'C-55876r815471_chk'
  tag severity: 'medium'
  tag gid: 'V-252420'
  tag rid: 'SV-252420r815473_rule'
  tag stig_id: 'KNOX-12-210150'
  tag gtitle: 'PP-MDF-323260'
  tag fix_id: 'F-55826r815472_fix'
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-002314']
  tag nist: ['AC-18 (1)', 'AC-17 (1)']
end
