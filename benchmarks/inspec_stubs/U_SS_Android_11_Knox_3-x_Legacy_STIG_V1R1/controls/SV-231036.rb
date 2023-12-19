control 'SV-231036' do
  title 'Samsung Android must [not accept the certificate] when it cannot establish a connection to determine the validity of a certificate.'
  desc 'Certificate-based security controls are dependent on the ability of the system to verify the validity of a certificate. If the MOS were to accept an invalid certificate, it could take unauthorized actions, resulting in unanticipated outcomes. At the same time, if the MOS were to disable functionality when it could not determine the validity of the certificate, this could result in a denial of service. Therefore, the ability to provide exceptions is appropriate to balance the tradeoff between security and functionality. Always accepting certificates when they cannot be determined to be valid is the most extreme exception policy and is not appropriate in the DoD context. Involving an Administrator or user in the exception decision mitigates this risk to some degree.

SFR ID: FIA_X509_EXT_2.2'
  desc 'check', 'Verify requirement KNOX-11-020200 (CC Mode) has been implemented.

If CC Mode has not been implemented, this is a finding.'
  desc 'fix', 'Implement CC Mode (see requirement KNOX-11-020200).'
  impact 0.3
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33966r592722_chk'
  tag severity: 'low'
  tag gid: 'V-231036'
  tag rid: 'SV-231036r608683_rule'
  tag stig_id: 'KNOX-11-014000'
  tag gtitle: 'PP-MDF-302490'
  tag fix_id: 'F-33939r592723_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
