control 'SV-241790' do
  title 'When the Jamf Pro EMM server cannot establish a connection to determine the validity of a certificate, the server must not have the option to accept the certificate.'
  desc 'When a Jamf Pro EMM server accepts an unverified certificate, it may be trusting a malicious actor. For example, messages signed with an invalid certificate may contain links to malware, which could lead to the installation or distribution of that malware on DoD information systems, leading to compromise of DoD sensitive information and other attacks.

SFR ID: FIA_X509_EXT.2.2'
  desc 'check', 'Validate the Jamf Pro EMM server has been configured to not accept a certificate if the certificate cannot be validated.

1. Open the Jamf Pro EMM console.
2. Open "Settings".
3. Select "User-Initiated Enrollment".
4. Under the General tab, verify "Use a third-party signing certificate" is selected.
5. Verify the name and certificate extension of the DoD p12 certificate is listed.

If the Jamf Pro EMM server has been not been configured to not accept a certificate if the certificate cannot be validated, this is a finding.'
  desc 'fix', 'Configure the Jamf Pro EMM server to not accept a certificate if the certificate cannot be validated.

1. Open the Jamf Pro EMM console.
2. Open "Settings".
3. Select "User-Initiated Enrollment".
4. Under the General tab, select "Use a third-party signing certificate".
5. Drag and drop the DoD p12 certificate.
6. Click "Save".'
  impact 0.5
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45066r685122_chk'
  tag severity: 'medium'
  tag gid: 'V-241790'
  tag rid: 'SV-241790r879612_rule'
  tag stig_id: 'JAMF-10-000040'
  tag gtitle: 'PP-MDM-412003'
  tag fix_id: 'F-45025r685123_fix'
  tag 'documentable'
  tag legacy: ['SV-108671', 'V-99567']
  tag cci: ['CCI-000185', 'CCI-000366', 'CCI-001310', 'CCI-002450']
  tag nist: ['IA-5 (2) (b) (1)', 'CM-6 b', 'SI-10', 'SC-13 b']
end
