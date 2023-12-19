control 'SV-255151' do
  title 'Samsung Android must be configured to enable authentication of personal hotspot connections to the device using a pre-shared key.'
  desc 'If no authentication is required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk.

Application note: If hotspot functionality is permitted, it must be authenticated via a preshared key. There is no requirement to enable hotspot functionality, and it is recommended this functionality be disabled by default.

SFR ID: FMT_SMF_EXT.1.1 #41'
  desc 'check', %q(Configure the Samsung Android devices to enable authentication of personal hotspot connections to the device using a pre-shared key.

On the management tool in the device restrictions, set "Configure tethering" to "Disallow".

If the deployment requires the use of Mobile Hotspot and Tethering, KPE policy can be used to allow its usage in a STIG-approved configuration. In this case, do not configure the policy above, and instead:

On the management tool, in the device Wi-Fi section, set "Unsecured hotspot" to "Disallow" and add Training Topic "Don't use Wi-Fi Sharing" (see supplemental document for additional information).)
  desc 'fix', %q(Configure the Samsung Android devices to enable authentication of personal hotspot connections to the device using a pre-shared key.

On the management tool in the device restrictions, set "Configure tethering" to "Disallow".

If the deployment requires the use of Mobile Hotspot and Tethering, KPE policy can be used to allow its usage in a STIG-approved configuration. In this case, do not configure the policy above, and instead:

On the management tool, in the device Wi-Fi section, set "Unsecured hotspot" to "Disallow" and add Training Topic "Don't use Wi-Fi Sharing" (see supplemental document for additional information).)
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58764r873671_chk'
  tag severity: 'medium'
  tag gid: 'V-255151'
  tag rid: 'SV-255151r873673_rule'
  tag stig_id: 'KNOX-13-210160'
  tag gtitle: 'PP-MDF-323260'
  tag fix_id: 'F-58708r873672_fix'
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-002314']
  tag nist: ['AC-18 (1)', 'AC-17 (1)']
end
