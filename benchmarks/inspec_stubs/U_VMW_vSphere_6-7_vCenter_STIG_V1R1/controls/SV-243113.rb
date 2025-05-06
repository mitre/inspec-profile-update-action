control 'SV-243113' do
  title 'The vCenter Server Machine SSL certificate must be issued by a DoD certificate authority.'
  desc 'The default self-signed, VMCA-issued vCenter reverse proxy certificate must be replaced with a DoD-approved certificate. The use of a DoD certificate on the vCenter reverse proxy assures clients that the service they are connecting to is legitimate and properly secured.'
  desc 'check', 'From the vSphere Client, go to Administration >> Certificates >> Certificate Management >> Machine SSL Certificate. 

Click "View Details". 

Examine the "Issuer Information" block.

If the issuer specified is not a DoD-approved certificate authority (or other AO approved CA), this is a finding.'
  desc 'fix', 'Obtain a DoD-issued certificate and private key for each vCenter in the system, following these requirements:

Key size: 2048 bits or more (PEM encoded)
CRT format (Base-64)
x509 version 3
SubjectAltName must contain DNS Name=<machine_FQDN>
Contains the following Key Usages: Digital Signature, Non Repudiation, Key Encipherment

Ensure that the certificate includes all intermediates and root certificates. If it does not, export the entire certificate issuing chain up to the root in Base-64 format and concatenate the individual certificates onto the issued certificate.

From the vSphere Client, go to Administration >> Certificates >> Certificate Management >> Machine SSL Certificate. 

Click Actions >> Replace. 

Supply the CA-issued certificate with the exported roots file and the private key. 

Click "Replace".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46388r719580_chk'
  tag severity: 'medium'
  tag gid: 'V-243113'
  tag rid: 'SV-243113r719582_rule'
  tag stig_id: 'VCTR-67-000058'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46345r719581_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
