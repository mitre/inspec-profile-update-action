control 'SV-234695' do
  title 'Oracle JRE 8 must lock the option to enable users to check publisher certificates for revocation.'
  desc 'Certificates may be revoked due to improper issuance, compromise of the certificate, and failure to adhere to policy. Therefore, any certificate found revoked on a CRL or via Online Certificate Status Protocol (OCSP) should not be trusted. Permitting execution of an applet published with a revoked certificate may result in spoofing, malware, system modification, invasion of privacy, and denial of service.

Ensuring users cannot change these settings assures a more consistent security profile.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level “deployment.properties” file for JRE.

The location of the deployment.properties file is defined in <JRE Installation Directory>\\Lib\\deployment.config

If the key “deployment.security.revocation.check=ALL_CERTIFICATES” is not present, or is set to “PUBLISHER_ONLY”, or “NO_CHECK”, this is a finding.

If the key “deployment.security.revocation.check.locked” is not present, this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level “deployment.properties” file for JRE.

The location of the deployment.properties file is defined in <JRE Installation Directory>\\Lib\\deployment.config

Add the key “deployment.security.revocation.check=ALL_CERTIFICATES” to the deployment.properties file.

Add the key “deployment.security.revocation.check.locked” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37880r616141_chk'
  tag severity: 'medium'
  tag gid: 'V-234695'
  tag rid: 'SV-234695r617446_rule'
  tag stig_id: 'JRE8-WN-000160'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37845r616142_fix'
  tag 'documentable'
  tag legacy: ['V-66723', 'SV-81213']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
