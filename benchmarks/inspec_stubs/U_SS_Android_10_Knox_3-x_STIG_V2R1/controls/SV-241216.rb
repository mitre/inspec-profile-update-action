control 'SV-241216' do
  title 'Samsung Android must [not accept the certificate] when it cannot establish a connection to determine the validity of a certificate.'
  desc 'Certificate-based security controls are dependent on the ability of the system to verify the validity of a certificate. If the MOS were to accept an invalid certificate, it could take unauthorized actions, resulting in unanticipated outcomes. At the same time, if the MOS were to disable functionality when it could not determine the validity of the certificate, this could result in a denial of service. Therefore, the ability to provide exceptions is appropriate to balance the tradeoff between security and functionality. Always accepting certificates when they cannot be determined to be valid is the most extreme exception policy and is not appropriate in the DoD context. Involving an Administrator or user in the exception decision mitigates this risk to some degree.

SFR ID: FIA_X509_EXT_2.2'
  desc 'check', 'Verify requirement KNOX-10-010800 (CC Mode) has been implemented.

If CC Mode has not been implemented, this is a finding.'
  desc 'fix', 'Verify CC Mode has been implemented (see requirement KNOX-10-010800).'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44492r680287_chk'
  tag severity: 'low'
  tag gid: 'V-241216'
  tag rid: 'SV-241216r680289_rule'
  tag stig_id: 'KNOX-10-007300'
  tag gtitle: 'PP-MDF-302490'
  tag fix_id: 'F-44451r680288_fix'
  tag 'documentable'
  tag legacy: ['SV-109065', 'V-99961']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
