control 'SV-239949' do
  title 'The Cisco ASA must be configured to validate certificates via a trustpoint that identifies a DoD or DoD-approved certificate authority.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted. To meet this requirement, the information system must create trusted channels between itself and remote trusted authorized IT product (e.g., syslog server) entities that protect the confidentiality and integrity of communications. The information system must create trusted paths between itself and remote administrators and users that protect the confidentiality and integrity of communications.

A trust anchor is an authoritative entity represented via a public key and associated data. It is most often used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC. However, applications that do not use a trusted path are not approved for non-local and remote management of DoD information systems.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'If PKI certificates are not implemented on the ASA, this requirement is not applicable.

Step 1: Review the ASA configuration to determine if a CA trust point has been configured as shown in the example below.

crypto ca trustpoint CA_X

Step 2: Verify the CA is a DoD or DoD-approved service provider by entering the following command: show crypto ca certificates

The output will list the following information for each certificate:

Associated Trustpoints: (will map to a configured trustpoint from Step 1)
Common Name (CN) of the issuer
Organization Unit (OU) of the issuer
Organization (O) of the issuer
Validity Date

If the ASA is not configured to obtain its public key certificates from a DoD or DoD-approved service provider, this is a finding.'
  desc 'fix', 'Ensure that certificate requests are only sent to DoD or DoD-approved service providers.'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43182r666251_chk'
  tag severity: 'medium'
  tag gid: 'V-239949'
  tag rid: 'SV-239949r666253_rule'
  tag stig_id: 'CASA-VN-000120'
  tag gtitle: 'SRG-NET-000164-VPN-000560'
  tag fix_id: 'F-43141r666252_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
