control 'SV-257136' do
  title 'The mobile device used for BYOAD must be NIAP validated.'
  desc 'Note: For a virtual mobile infrastructure (VMI) solution, both the client and server must be NIAP compliant.

Nonapproved mobile devices may not include sufficient controls to protect work data, applications, and networks from malware or adversary attack. 

Components must only approve devices listed on the NIAP product compliant list or products listed in evaluation at the following links respectively:
- https://www.niap-ccevs.org/Product/
- https://www.niap-ccevs.org/Product/PINE.cfm

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(2)).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the mobile device used for BYOAD is NIAP validated (included on the NIAP list of compliant products or products in evaluation). 

If the mobile device used for BYOAD is not NIAP validated (included on the NIAP list of compliant products or products in evaluation), this is a finding.'
  desc 'fix', 'Use only mobile devices for BYOAD that are NIAP validated (included on the NIAP list of compliant products or products in evaluation).'
  impact 0.7
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60821r904454_chk'
  tag severity: 'high'
  tag gid: 'V-257136'
  tag rid: 'SV-257136r904500_rule'
  tag stig_id: 'AIOS-16-800280'
  tag gtitle: 'PP-BYO-000200'
  tag fix_id: 'F-60762r904455_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
