control 'SV-257100' do
  title 'The EMM system supporting the iOS/iPadOS 16 BYOAD must be NIAP validated (included on the NIAP list of compliant products or products in evaluation) unless the DOD CIO has granted an approved Exception to Policy (E2P).'
  desc 'Note: For a virtual mobile infrastructure (VMI) solution, both the client and server must be NIAP compliant.

Nonapproved EMM systems may not include sufficient controls to protect work data, applications, and networks from malware or adversary attack. EMM systems include mobile device management (MDM), mobile application management (MAM), mobile content management (MCM), or VMI. 

Components must only approve devices listed on the NIAP product compliant list or products listed in evaluation at the following links respectively:
- https://www.niap-ccevs.org/Product/
- https://www.niap-ccevs.org/Product/PINE.cfm

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.a.(2).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system supporting the iOS/iPadOS BYOAD is NIAP validated (included on the NIAP list of compliant products or products in evaluation). 

If it is not, verify the DOD CIO has granted an approved E2P.

Note: For a VMI solution, both the client and server components must be NIAP compliant.

If the EMM system supporting the iOS/iPadOS BYOAD is not NIAP validated (included on the NIAP list of compliant products or products in evaluation) and the DOD CIO has not granted an approved E2P, this is a finding.'
  desc 'fix', 'Only use an EMM system supporting the iOS/iPadOS 16 BYOAD that is NIAP validated (included on the NIAP list of compliant products or products in evaluation) unless the DOD CIO has granted an approved E2P.

Note: For a VMI solution, both the client and server components must be NIAP compliant.'
  impact 0.7
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60785r904043_chk'
  tag severity: 'high'
  tag gid: 'V-257100'
  tag rid: 'SV-257100r904452_rule'
  tag stig_id: 'AIOS-16-800200'
  tag gtitle: 'PP-BYO-000200'
  tag fix_id: 'F-60726r904044_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
