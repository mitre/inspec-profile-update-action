control 'SV-81411' do
  title 'Oracle JRE 8 must set the option to enable online certificate validation.'
  desc 'Online certificate validation provides a real-time option to validate a certificate.  When enabled, if a certificate is presented, the status of the certificate is requested.  The status is sent back as “current”, “expired”, or “unknown”.  Online certificate validation provides a greater degree of validation of certificates when running a signed Java applet.   Permitting execution of an applet with an invalid certificate may result in malware, system modification, invasion of privacy, and denial of service.'
  desc 'check', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level “deployment.properties” file for JRE.

 /etc/.java/deployment/deployment.properties

If the key “deployment.security.validation.ocsp=true” is not present in the deployment.properties file, this is a finding.

If the key “deployment.security.validation.ocsp.locked” is not present in the deployment.properties file, this is a finding.

If the key “deployment.security.validation.ocsp” is set to “false”, this is a finding.'
  desc 'fix', 'If the system is on the SIPRNet, this requirement is NA.

Navigate to the system-level “deployment.properties” file for JRE.

/etc/.java/deployment/deployment.properties

Add the key “deployment.security.validation.ocsp=true” to the deployment.properties file.

Add the key “deployment.security.validation.ocsp.locked” to the deployment.properties file.'
  impact 0.5
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67557r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66921'
  tag rid: 'SV-81411r1_rule'
  tag stig_id: 'JRE8-UX-000100'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-73021r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
