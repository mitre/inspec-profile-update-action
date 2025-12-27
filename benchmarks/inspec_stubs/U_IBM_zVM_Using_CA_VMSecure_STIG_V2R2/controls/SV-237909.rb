control 'SV-237909' do
  title 'All digital certificates in use must have a valid path to a trusted Certification authority.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', %q(Invoke the "gskkyman" utility.

From the "Key Management" Menu display Certificate Information.

If no certificate information is found, this is not a finding.

Note: Certificates are only valid when their status is "TRUST". Therefore, you may ignore certificates with the "NOTRUST" status during the following checks.

If the digital certificate information indicates that the issuer's distinguished name leads to a DoD PKI Root Certificate Authority or External Certification Authority (ECA), this is not a finding.

Reference the Cyber Exchange website for complete information as to which certificates are acceptable (https://cyber.mil/pki-pke/pkipke-document-library/).)
  desc 'fix', "Remove or and replace certificates whose issuer's distinguished name does not lead to a DoD PKI Root Certification Authority, External Root Certification Authority (ECA), or an approved External Partner PKI's Root Certification Authority."
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41119r858949_chk'
  tag severity: 'medium'
  tag gid: 'V-237909'
  tag rid: 'SV-237909r858951_rule'
  tag stig_id: 'IBMZ-VM-000460'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-41078r858950_fix'
  tag 'documentable'
  tag legacy: ['SV-93571', 'V-78865']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
