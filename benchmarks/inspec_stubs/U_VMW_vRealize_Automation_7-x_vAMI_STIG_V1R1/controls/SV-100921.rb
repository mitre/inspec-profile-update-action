control 'SV-100921' do
  title 'The vAMI sfcb server certificate must only be accessible to authenticated system administrators or the designated PKI Sponsor.'
  desc 'An asymmetric encryption key must be protected during transmission. The public portion of an asymmetric key pair can be freely distributed without fear of compromise, and the private portion of the key must be protected. The application server will provide software libraries that applications can programmatically utilize to encrypt and decrypt information. These application server libraries must use NIST-approved or NSA-approved key management technology and processes when producing, controlling, or distributing symmetric and asymmetric keys.'
  desc 'check', 'At the command prompt, execute the following command:

ls -l /opt/vmware/etc/sfcb/server.pem

If permissions on the certificate file is not -r--r----- (440), this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chmod 440 /opt/vmware/etc/sfcb/server.pem'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89963r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90271'
  tag rid: 'SV-100921r1_rule'
  tag stig_id: 'VRAU-VA-000635'
  tag gtitle: 'SRG-APP-000514-AS-000136'
  tag fix_id: 'F-97013r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
