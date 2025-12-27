control 'SV-242639' do
  title 'The Cisco ISE must use DoD-approved PKI rather than proprietary or self-signed device certificates.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs.

The Cisco ISE generates a key-pair and a CSR. The CSR is sent to the approved CA, who signs it and returns it as a certificate. That certificate is then installed. 

The process to obtain a device PKI certificate requires the generation of a Certificate Signing Request (CSR), submission of the CSR to a CA, approval of the request by an RA, and retrieval of the issued certificate from the CA.'
  desc 'check', 'Choose Administration >> System >> Certificates >> System Certificates.

1. The System Certificates page appears and provides information for the local certificates.
2. Select a certificate and choose "View" to display the certificate details.

If the Cisco ISE does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Replace the self-signed certificate with a CA-signed certificates for greater security. To obtain a CA-signed certificate:

A. Generate a certificate signing request (CSR) to obtain a CA-signed certificate for the nodes in your deployment.
1. Choose Administration >> System >> Certificates >> Certificate Signing Requests.
2. Enter the values for generating a CSR.
Examples:
RSA:
Request security pki generate-key-pair certificate-id <cert name>> type rsa size <512 | 1024 | 2048 | 4096>>
ECDSA:
Request security pki generate-key-pair certificate-id <cert_name>> type ecdsa size <256 | 384>>
3. Click "Generate" to generate the CSR.
4. Click "Export" to open the CSR in a Notepad.
5. Copy all the text from "-----BEGIN CERTIFICATE REQUEST-----" through "-----END CERTIFICATE REQUEST-----."
6. Paste the contents of the CSR into the certificate request. Generate a new key-pair from a DoD-approved certificate issuer. Sites must consult the PKI/PKI pages on the https://cyber.mil/ website for procedures for NIPRNet and SIPRNet.
7. Download the signed certificate.

B. Import the Root Certificates to the Trusted Certificate Store:
Administration >> System >> Certificates >> Trusted Certificates

C. Bind the CA-Signed Certificate to the CSR.
1. Choose Administration >> System >> Certificates >> Certificate Signing Requests. Check the check box next to the node for which you are binding the CSR with the CA-signed certificate.
2.  Click "Bind".
3.  Click "Browse" to choose the CA-signed certificate.
4.  Specify a Friendly Name for the certificate.
5.  Check the "Validate Certificate Extensions" check box if you want Cisco ISE to validate certificate extensions.
6. Check the service for which this certificate will be used in the Usage area.
This information is auto populated if you have enabled the Usage option while generating the CSR. If you do not want to specify the usage at the time of binding the certificate, uncheck the Usage option. You can edit the certificate later and specify the usage.
7. Click "Submit". If you have chosen to use this certificate for Cisco ISE internode communication, the application server on the Cisco ISE node is restarted.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45914r714225_chk'
  tag severity: 'medium'
  tag gid: 'V-242639'
  tag rid: 'SV-242639r714227_rule'
  tag stig_id: 'CSCO-NM-000340'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-45871r714226_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
