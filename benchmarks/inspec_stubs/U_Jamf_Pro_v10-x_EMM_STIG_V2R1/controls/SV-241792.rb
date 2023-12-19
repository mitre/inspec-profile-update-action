control 'SV-241792' do
  title 'The Jamf Pro EMM server must be configured with an enterprise certificate for signing policies (if function is not automatically implemented during Jamf Pro EMM server install).'
  desc 'It is critical that only authorized certificates are used for key activities such as code signing for system software updates, code signing for integrity verification, and policy signing. Otherwise, there is no assurance that a malicious actor has not inserted itself in the process of packaging the code or policy. For example, messages signed with an invalid certificate may contain links to malware, which could lead to the installation or distribution of that malware on DoD information systems, leading to compromise of DoD sensitive information and other attacks. Therefore, the Jamf Pro EMM server must have the capability to configure the enterprise certificate.

SFR ID: FMT_SMF.1.1(2) i, FMT_POL_EXT.1.1'
  desc 'check', 'Verify Jamf Pro is utilizing an External CA for signing communication to mobile devices:

1. Open Jamf Pro server.
2. Open "Settings".
3. Select "PKI Certificates".
4. Select "Management Certificate Template".
5. Select "External CA" tab.
6. Verify the "Use a SCEP-enabled external CA for computer and mobile device enrollment" is enabled.
7. Verify that the Signing Certificate is listed at the bottom of the page.

If these settings are confirmed, Jamf Pro is set to use an external CA.

If Jamf Pro is not configured to use an External CA for signing communication to mobile devices, this is a finding.'
  desc 'fix', 'Configure the following settings within the Jamf Pro EMM server for ensuring an authorized DoD certificate is used for signing enrollment and configuration profiles:

1. Open Jamf Pro server.
2. Open "Settings".
3. Open "PKI Certificates".
4. Select "Management Certificate Template" tab.
5. Select "External CA" tab.
6. Select "Edit".
7. Select to use SCEP-enabled external CA for computer and mobile device enrollment.
8. Enter all the applicable settings to connect this server to SCEP/Entrust enabled CA.
9. Select "Save".
10. At the bottom of the External CA screen, select "Change Signing and CA Certificates".
11. Follow onscreen instructions to upload the signing and CA certificates for Jamf Pro to use.

Jamf Pro is now set to use an External CA for signing all communication to mobile devices.'
  impact 0.5
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45068r685128_chk'
  tag severity: 'medium'
  tag gid: 'V-241792'
  tag rid: 'SV-241792r879887_rule'
  tag stig_id: 'JAMF-10-000480'
  tag gtitle: 'PP-MDM-411051'
  tag fix_id: 'F-45027r685129_fix'
  tag 'documentable'
  tag legacy: ['SV-108677', 'V-99573']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
