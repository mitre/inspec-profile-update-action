control 'SV-258470' do
  title 'The EMM system supporting the Google Android 13 BYOAD must be NIAP validated (included on the NIAP list of compliant products or products in evaluation) unless the DOD CIO has granted an Approved Exception to Policy (E2P).'
  desc 'Note: For a VMI solution, both the client and server must be NIAP compliant.

Nonapproved EMM systems may not include sufficient controls to protect work data, applications, and networks from malware or adversary attack. EMM: mobile device management (MDM), mobile application management (MAM), mobile content management (MCM), and virtual mobile infrastructure (VMI). 

Components must only approve devices listed on the NIAP product compliant list or products listed in evaluation at the following links respectfully:
- https://www.niap-ccevs.org/Product/
- https://www.niap-ccevs.org/Product/PINE.cfm

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(2)).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system supporting the Google Android 13 BYOAD is NIAP-validated (included on the NIAP list of compliant products or products in evaluation). If not, verify the DOD CIO has granted an Approved Exception to Policy (E2P).

Note: For a VMI solution, both the client and server components must be NIAP compliant.

If the EMM system supporting the Google Android 13 BYOAD is not NIAP-validated (included on the NIAP list of compliant products or products in evaluation) and the DOD CIO has not granted an Approved Exception to Policy (E2P), this is a finding.'
  desc 'fix', 'Only use an EMM system supporting the Google Android 13 BYOAD that is NIAP validated (included on the NIAP list of compliant products or products in evaluation), unless the DOD CIO has granted an Approved Exception to Policy (E2P).

Note: For a VMI solution, both the client and server components must be NIAP compliant.'
  impact 0.7
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62210r929224_chk'
  tag severity: 'high'
  tag gid: 'V-258470'
  tag rid: 'SV-258470r929226_rule'
  tag stig_id: 'GOOG-13-802000'
  tag gtitle: 'PP-BYO-000200'
  tag fix_id: 'F-62119r929225_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
