control 'SV-223648' do
  title 'All digital certificates in use must have a valid path to a trusted Certification authority.'
  desc 'The origin of a certificate, the Certificate Authority (i.e., CA), is crucial in determining if the certificate should be trusted. An approved CA establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted.

'
  desc 'check', "From the ISPF Command Shell enter:
RACDCERT CERT AUTH

If no certificate information is found, this is not a finding.

NOTE: Certificates are only valid when their Status is TRUST. Therefore, you may ignore certificates with the NOTRUST status during the following check.

If the digital certificate information indicates that the issuer's distinguished name leads to one of the following, this is not a finding:
a)	A DoD PKI Root Certification Authority
b)	An External Root Certification Authority (ECA)
c)	An approved External Partner PKI’s Root Certification Authority

The DoD Cyber Exchange website contains information as to which certificates maybe acceptable (https://public.cyber.mil/pki-pke/interoperability/ or https://cyber.mil/pki-pke/interoperability/).

Examples of an acceptable DoD CA are:
DoD PKI Class 3 Root CA
DoD PKI Med Root CA"
  desc 'fix', "Remove and/or replace certificates with a status of TRUST whose issuer's distinguished name does not lead to a DoD PKI Root Certification Authority, External Root Certification Authority (ECA), or an approved External Partner PKI’s Root Certification Authority.

Reference the DoD Cyber Exchange website for complete information as to which certificates may be acceptable (https://public.cyber.mil/pki-pke/interoperability/ or https://cyber.mil/pki-pke/interoperability/)."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25321r803630_chk'
  tag severity: 'medium'
  tag gid: 'V-223648'
  tag rid: 'SV-223648r803632_rule'
  tag stig_id: 'RACF-CE-000030'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-25309r803631_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000403-GPOS-00182']
  tag 'documentable'
  tag legacy: ['V-98001', 'SV-107105']
  tag cci: ['CCI-000185', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-23 (5)']
end
