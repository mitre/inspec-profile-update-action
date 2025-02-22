control 'SV-100923' do
  title 'If the vAMI uses PKI Class 3 or Class 4 certificates, the certificates must be DoD- or CNSS-approved.

If the vAMI does not use PKI Class 3 or Class 4 certificates, this requirement is Not Applicable.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The vAMI must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc 'check', 'Interview the ISSO and/or the SA.

Determine if the vAMI is using PKI Class 3 or Class 4 certificates.

If the vAMI is using PKI Class 3 or Class 4 certificates, and the certificates are not DoD- or CNSS-approved, this is a finding.'
  desc 'fix', 'If the vAMI is using PKI Class 3 or Class 4 certificates, install certificates that are DoD or CNSS approved.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89965r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90273'
  tag rid: 'SV-100923r1_rule'
  tag stig_id: 'VRAU-VA-000640'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag fix_id: 'F-97015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
