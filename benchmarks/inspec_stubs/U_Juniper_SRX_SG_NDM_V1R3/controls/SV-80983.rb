control 'SV-80983' do
  title 'The Juniper SRX Services Gateway must use DoD-approved PKI rather than proprietary or self-signed device certificates.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs.

The SRX generates a key-pair and a CSR. The CSR is sent to the approved CA, who signs it and returns it as a certificate. That certificate is then installed. 

The process to obtain a device PKI certificate requires the generation of a Certificate Signing Request (CSR), submission of the CSR to a CA, approval of the request by an RA, and retrieval of the issued certificate from the CA.'
  desc 'check', 'To validate that the certificate was loaded, type the following command:

show security pki local-certificate

View the installed device certificates.

If any of the certificates have the name or identifier of a non-approved source in the Issuer field, this is a finding.'
  desc 'fix', 'Generate a new key-pair from a DoD-approved certificate issuer. Sites must consult the PKI/PKI pages on the http://iase.disa.mil/ website for procedures for NIPRNet and SIPRNet.

RSA:
request security pki generate-key-pair certificate-id <cert name> type rsa size <512 | 1024 | 2048 | 4096>

ECDSA:
request security pki generate-key-pair certificate-id <cert_name> type ecdsa size <256 | 384>

Generate a CSR from RSA key-pair using the following command and options.

request security generate-certificate-request certificate-id <cert_name_from_key_file> digest <sha1 | sha256> domain <FQDN> email <admin_email> ip-address <ip_address> subject “CN=<hostname>,DC=<domain_part>,DC=<TLD_domain>,O=<organization>,OU=<organization_dept>,
L=<city>,ST=<state>,C=<us>” filename <path/filename>

Generate a CSR from ECDSA key-pair use the following command and options.

request security generate-certificate-request certificate-id <cert_name_from_key_file> digest <sha256 | sha384> domain <FQDN> email <admin_email> ip-address <ip_address> subject “CN=<hostname>,DC=<domain_part>,DC=<TLD_domain>,O=<organization>,OU=<organization_dept>,
L=<city>,ST=<state>,C=<us>” filename <path/filename>

If no filename is specified, the CSR is displayed on the standard out (terminal)

After receiving the approved certificate from the CA, enter the following command and options to upload the certificate.

request security pki local-certificate certificate-id <cert_name_from_key_file> filename <path/filename_of_uploaded_certificate>

From the operational mode of the hierarchy:

set security certificates local new load-key-file /var/tmp/new.pem 

Type the following command to load the X.509 certificate into the certificate store in operations mode.

>request security pki local-certificate load certificate-id <ID> filename <PATH TO CERTIFICATE FILE>

For this example, assume the transferred the X.509 certificate called "device-cert.crt" to the /var/tmp directory on the SRXD. The following command will load the device-cert.crt certificate file and associate it with the public/private keypair named “device-keypair” generated in a previous step.

>request security pki local-certificate load certificate-id device-keypair filename /var/tmp/device-cert.crt'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66493'
  tag rid: 'SV-80983r1_rule'
  tag stig_id: 'JUSX-DM-000105'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-72569r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
