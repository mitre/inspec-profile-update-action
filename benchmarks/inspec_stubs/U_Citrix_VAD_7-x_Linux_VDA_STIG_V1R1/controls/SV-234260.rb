control 'SV-234260' do
  title 'Citrix Linux Virtual Delivery Agent must only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Verify the correct server certificate issued by authorized certificate authority is installed on Linux VDA.
Navigate to folder /root/myCert/myCA/certs/ and examine certificates.
If the certificates are not issued by the DoD or approved CA, this is a finding.'
  desc 'fix', 'A server certificate must be installed on each Linux VDA server and root certificates must be installed on each Linux VDA server and client.
Obtain server certificates in PEM format and root certificates in CRT format from a trusted CA. A server certificate contains the following sections:
- Certificate
- Unencrypted private key
- Intermediate certificates (optional)

After obtaining required certificates, customers need to install them as follows:
Upload server and CA certificates into Linux VDA server, which will be used in “Step 2: Enable SSL encryption on Linux VDA”. For example, put server.pem (name of server certificate) and myca.crt (name of CA certificate) to folder /root/myCert/myCA/certs/.

Download the CA certificate (myca.crt as an example) to client host and import it into system Certificate Store on the “Trusted Root Certification Authorities” folder. Refer to "Importing Trusted CA Certificates into the Windows Certificate Store" for the instructions. Note: Ensure the client host is able to resolve the FQDN of Linux VDA; otherwise, the connection cannot be established.'
  impact 0.7
  ref 'DPMS Target Citrix VAD 7.x LVDA'
  tag check_id: 'C-37445r612334_chk'
  tag severity: 'high'
  tag gid: 'V-234260'
  tag rid: 'SV-234260r628796_rule'
  tag stig_id: 'LVDA-VD-000970'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-37410r612335_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
