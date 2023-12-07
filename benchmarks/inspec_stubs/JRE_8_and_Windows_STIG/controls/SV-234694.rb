control 'SV-234694' do
  title 'Oracle JRE 8 must enable the dialog to enable users to check publisher certificates for revocation.'
  desc 'A certificate revocation list is a directory which contains a list of certificates that have been revoked for various reasons. Certificates may be revoked due to improper issuance, compromise of the certificate, and failure to adhere to policy. Therefore, any certificate found on a CRL should not be trusted. Permitting execution of an applet published with a revoked certificate may result in spoofing, malware, system modification, invasion of privacy, and denial of service.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level "deployment.properties" file for JRE.

<Windows Directory>\\Sun\\Java\\Deployment\\deployment.properties
- or -
<JRE Installation Directory>\\Lib\\deployment.properties

If the key "deployment.security.validation.crl=true" is not present in the "deployment.properties" file, or is set to "false", this is a finding.

If the key "deployment.security.validation.crl.locked" is not present in the "deployment.properties" file, this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Enable the "Check certificates for revocation using If the system is on the SIPRNet, this requirement is NA.

Enable the "Check certificates for revocation using Certificate Revocation Lists (CRL)" option.

Navigate to the system-level "deployment.properties" file for JRE.

Add the key "deployment.security.validation.crl=true" to the "deployment.properties" file.

Add the key "deployment.security.validation.crl.locked" to the "deployment.properties" file.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37879r616138_chk'
  tag severity: 'medium'
  tag gid: 'V-234694'
  tag rid: 'SV-234694r617446_rule'
  tag stig_id: 'JRE8-WN-000150'
  tag gtitle: 'SRG-APP-000401'
  tag fix_id: 'F-37844r616139_fix'
  tag 'documentable'
  tag legacy: ['V-66961', 'SV-81451']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
