control 'SV-223871' do
  title 'All IBM z/OS digital certificates in use must have a valid path to a trusted Certification Authority (CA).'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a CA. A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.

'
  desc 'check', "Execute the CA-TSS SAFCRRPT using the following as SYSIN input:
RECORDID(-) DETAIL TRUST FIELDS(ISSUER SUBJECT ACTIVE EXPIRE TRUST)

If no certificate information is found, this is not a finding.

NOTE: Certificates are only valid when their Status is TRUST. Therefore, you may ignore certificates with the NOTRUST status during the following check.

If the digital certificate information indicates that the issuer's distinguished name leads to one of the following this is not a finding:
a)	A DoD PKI Root Certification Authority
b)	An External Root Certification Authority (ECA)
c)	An approved External Partner PKI’s Root Certification Authority

The DoD Cyber Exchange website contains information as to which certificates may be acceptable (https://public.cyber.mil/pki-pke/interoperability/ or https://cyber.mil/pki-pke/interoperability/).

Examples of an acceptable DoD CA are:
DoD PKI Class 3 Root CA
DoD PKI Med Root CA"
  desc 'fix', "Remove or replace certificates where the issuer's distinguished name does not lead to a DoD PKI Root Certification Authority; External Root Certification Authority (ECA); or an approved External Partner PKI’s Root Certification Authority.

The DoD Cyber Exchange website contains information as to which certificates may be acceptable (https://public.cyber.mil/pki-pke/interoperability/ or https://cyber.mil/pki-pke/interoperability/)."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25544r803643_chk'
  tag severity: 'medium'
  tag gid: 'V-223871'
  tag rid: 'SV-223871r856060_rule'
  tag stig_id: 'TSS0-CE-000010'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-25532r803644_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000403-GPOS-00182']
  tag 'documentable'
  tag legacy: ['SV-107553', 'V-98449']
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end
