control 'SV-216877' do
  title 'The vCenter Server for Windows reverse proxy must use DoD approved certificates.'
  desc 'The default self-signed, VMCA issued vCenter reverse proxy certificate must be replaced with a DoD approved certificate. The use of a DoD certificate on the vCenter reverse proxy assures clients that the service they are connecting to is legitimate and properly secured.'
  desc 'check', 'From the vCenter server (and external PSC if appropriate) run the following command

Appliance:
/usr/lib/vmware-vmafd/bin/vecs-cli entry getcert --store machine_ssl_cert --alias __MACHINE_CERT --text|grep Issuer

Windows:
"C:\\Program Files\\VMware\\vCenter Server\\vmafdd\\vecs-cli.exe" entry getcert --store machine_ssl_cert --alias __MACHINE_CERT --text|find "Issuer"

If the issuer is not a DoD approved certificate authority, or other AO approved certificate authority, this is a finding.'
  desc 'fix', 'Obtain a DoD issued certificate and private key for each vCenter and external PSC in the system, following the below requirements:

Key size: 2048 bits or more (PEM encoded)
CRT format (Base-64)
x509 version 3
SubjectAltName must contain DNS Name=<machine_FQDN>
Contains the following Key Usages: Digital Signature, Non Repudiation, Key Encipherment

Verify that the issued certificate includes the full issuing chain. If it does not, concatenate the Base-64 intermediates and root onto the issued machine ssl cert.

Export the entire certificate issuing chain up to the root in Base-64 format, concatenate the individual certs into one file that will be used in the next steps when prompted for the signing certificate.

Run the certificate-manager tool:

Appliance:
/usr/lib/vmware-vmca/bin/certificate-manager

Windows:
C:\\Program Files\\VMware\\vCenter Server\\vmcad\\certificate-manager.bat

Select option "1" to replace the machine ssl certificate. Select option "2" to specify existing certificate and private key. Supply the information as prompted remembering the signing certificate file built up previously.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18108r622446_chk'
  tag severity: 'medium'
  tag gid: 'V-216877'
  tag rid: 'SV-216877r879887_rule'
  tag stig_id: 'VCWN-65-000058'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18106r366346_fix'
  tag 'documentable'
  tag legacy: ['SV-104649', 'V-94819']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
