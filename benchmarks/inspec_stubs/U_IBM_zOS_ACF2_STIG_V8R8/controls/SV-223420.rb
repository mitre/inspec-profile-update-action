control 'SV-223420' do
  title 'IBM z/OS must not use Expired Digital Certificates.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', "Execute the CA-ACF2 SAFCRRPT using the following as SYSIN input
RECORDID(-) DETAIL FIELDS(ISSUER SUBJECT ACTIVE EXPIRE TRUST)

If no certificate information is found, this is not a finding.

NOTE: Certificates are only valid when their Status is TRUST. Therefore, you may ignore certificates with the NOTRUST status during the following checks.

If the digital certificate information indicates that the issuer's distinguished name leads to a DoD PKI Root Certificate Authority or External Certification Authority (ECA), this is not a finding. 

Reference the DoD Cyber Exchange website for complete information as to which certificates are acceptable (https://cyber.mil/pki-pke/interoperability/).

Examples of an acceptable DoD CA are:
DoD PKI Class 3 Root CA
DoD PKI Med Root CA"
  desc 'fix', 'If the certificate is a user or device certificate with a status of trust, follow procedures to obtain a new certificate or re-key certificate. If it is an expired CA certificate remove it.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25093r500390_chk'
  tag severity: 'medium'
  tag gid: 'V-223420'
  tag rid: 'SV-223420r533198_rule'
  tag stig_id: 'ACF2-CE-000020'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-25081r500391_fix'
  tag 'documentable'
  tag legacy: ['SV-106641', 'V-97537']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
