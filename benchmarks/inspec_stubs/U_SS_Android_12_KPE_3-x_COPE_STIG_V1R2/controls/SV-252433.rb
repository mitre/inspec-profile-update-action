control 'SV-252433' do
  title 'Samsung Android must not accept the certificate when it cannot establish a connection to determine the validity of a certificate.'
  desc 'Certificate-based security controls depend on the ability of the system to verify the validity of a certificate. If the MOS were to accept an invalid certificate, it could take unauthorized actions, resulting in unanticipated outcomes. At the same time, if the MOS were to disable functionality when it could not determine the validity of the certificate, this could result in a denial of service. Therefore, the ability to provide exceptions is appropriate to balance the tradeoff between security and functionality. Always accepting certificates when they cannot be determined to be valid is the most extreme exception policy and is not appropriate in the DoD context. Involving an Administrator or user in the exception decision mitigates this risk to some degree.

SFR ID: FIA_X509_EXT_2.2'
  desc 'check', 'Verify requirement KNOX-12-210270 (CC Mode) has been implemented.

If "CC Mode" has not been implemented, this is a finding.'
  desc 'fix', 'Implement CC Mode (see requirement KNOX-12-210270).'
  impact 0.3
  ref 'DPMS Target Samsung Android 12 KPE 3.x COPE'
  tag check_id: 'C-55889r815510_chk'
  tag severity: 'low'
  tag gid: 'V-252433'
  tag rid: 'SV-252433r815512_rule'
  tag stig_id: 'KNOX-12-210280'
  tag gtitle: 'PP-MDF-321080'
  tag fix_id: 'F-55839r815511_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
