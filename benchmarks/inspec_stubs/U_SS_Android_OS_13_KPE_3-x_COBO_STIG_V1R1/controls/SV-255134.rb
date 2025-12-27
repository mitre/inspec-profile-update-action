control 'SV-255134' do
  title 'Samsung Android must not accept the certificate when it cannot establish a connection to determine the validity of a certificate.'
  desc 'Certificate-based security controls depend on the ability of the system to verify the validity of a certificate. If the MOS were to accept an invalid certificate, it could take unauthorized actions, resulting in unanticipated outcomes. At the same time, if the MOS were to disable functionality when it could not determine the validity of the certificate, this could result in a denial of service. Therefore, the ability to provide exceptions is appropriate to balance the tradeoff between security and functionality. Always accepting certificates when they cannot be determined to be valid is the most extreme exception policy and is not appropriate in the DOD context. Involving an Administrator or user in the exception decision mitigates this risk to some degree.

SFR ID: FIA_X509_EXT_2.2'
  desc 'check', 'Verify requirement KNOX-13-110280 (Common Criteria mode) has been implemented.

If "Common Criteria mode" has not been implemented, this is a finding.'
  desc 'fix', 'Implement "Common Criteria mode" (see requirement KNOX-13-110280).'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58747r867337_chk'
  tag severity: 'low'
  tag gid: 'V-255134'
  tag rid: 'SV-255134r867339_rule'
  tag stig_id: 'KNOX-13-110290'
  tag gtitle: 'PP-MDF-321080'
  tag fix_id: 'F-58691r867338_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
