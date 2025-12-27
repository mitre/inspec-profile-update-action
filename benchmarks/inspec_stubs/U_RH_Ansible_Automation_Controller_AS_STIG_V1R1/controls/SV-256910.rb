control 'SV-256910' do
  title 'Automation Controller must only allow the use of DOD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'An untrusted source may leave the system vulnerable to issues such as unauthorized access, reduced data integrity, loss of confidentiality, etc.

'
  desc 'check', 'The Administrator must check the Automation Controller configuration. 

Download the latest DOD PKI CA certificate bundle:

curl https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_DOD.zip > /root/certificates_pkcs7_DOD.zip && gunzip /root/certificates_pkcs7_DOD.zip

Check the certificate at /etc/tower/tower.cert:

openssl verify -verbose -x509_strict -CAfile /root/certificates_pkcs7_DOD.pem -CApath nosuchdir <(cat  /etc/tower/tower.cert >><organizationally defined intermediate certificate file in PEM format>>>)

If the >><organizationally defined intermediate certificate file in PEM format>>> does not exist, this is a finding.

Check the certificate at /etc/tower/tower.key:
openssl verify -CAfile /root/certificates_pkcs7_DOD.pem /etc/tower/tower.cert  

If the >><organizationally defined intermediate certificate file in PEM format>>> does not exist, this is a finding.

Check the trusted ca certificate:

openssl x509 -in /etc/pki/ca-trust/tls-ca-bundle.pam custom_ca_cert

If the >><organizationally defined intermediate certificate file in PEM format>>> does not exist, this is a finding.

If the >><organizationally defined intermediate certificate file in PEM format>>> does not exist, this is a finding.'
  desc 'fix', 'For each Automation Controller host, the administrator must:

Download the >><organizationally defined intermediate certificate file in PEM format>>>;

Generate the appropriate /etc/tower/tower.key files, certificates, and CSRs and have the organizationally defined PKI authority issue a certificate signed by the >><organizationally defined intermediate certificate file in PEM format>>>;

Place the signed certificate in /etc/tower/tower.cert.

Place the >><organizationally defined intermediate certificate file in PEM format>>> in /etc/pki/ca-trust/source/anchors.

Execute:
update-ca-trust extract && update-ca-trust;

Download the latest DOD PKI CA certificate bundle:

curl https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_DOD.zip > /root/certificates_pkcs7_DOD.z && gunzip /root/certificates_pkcs7_DOD.z > /etc/pki/ca-trust/source/anchors

Install trusted root and intermediate CA certificates:

update-ca-trust extract && update-ca-trust;'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60585r902298_chk'
  tag severity: 'medium'
  tag gid: 'V-256910'
  tag rid: 'SV-256910r902300_rule'
  tag stig_id: 'APAS-AT-000110'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-60527r902299_fix'
  tag satisfies: ['SRG-APP-000427-AS-000264', 'SRG-APP-000514-AS-000137']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002470']
  tag nist: ['SC-13 b', 'SC-23 (5)']
end
