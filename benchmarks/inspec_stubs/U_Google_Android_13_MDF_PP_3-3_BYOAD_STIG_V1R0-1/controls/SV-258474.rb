control 'SV-258474' do
  title 'The mobile device used for BYOAD must be NIAP validated.'
  desc 'Nonapproved mobile devices may not include sufficient controls to protect work data, applications, and networks from malware or adversary attack.

Components must only approve devices listed on the NIAP product compliant list or products listed in evaluation at the following links respectfully:
- https://www.niap-ccevs.org/Product/
- https://www.niap-ccevs.org/Product/PINE.cfm

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.b.(1)i).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the mobile device used for BYOAD is NIAP validated (included on the NIAP list of compliant products or products in evaluation). 

If the mobile device used for BYOAD is not NIAP validated (included on the NIAP list of compliant products or products in evaluation), this is a finding.'
  desc 'fix', 'Use only mobile devices for BYOAD that are NIAP validated (included on the NIAP list of compliant products or products in evaluation).'
  impact 0.7
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62214r929236_chk'
  tag severity: 'high'
  tag gid: 'V-258474'
  tag rid: 'SV-258474r929238_rule'
  tag stig_id: 'GOOG-13-802800'
  tag gtitle: 'PP-BYO-000200'
  tag fix_id: 'F-62123r929237_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
