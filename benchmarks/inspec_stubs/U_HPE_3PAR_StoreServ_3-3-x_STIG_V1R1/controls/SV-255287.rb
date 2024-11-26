control 'SV-255287' do
  title 'The HPE 3PAR OS must be configured to only allow the use of DOD PKI-established certificate authorities for authentication in the establishment of protected sessions to the operating system.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

The DOD will only accept PKI-certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

The HPE 3PAR OS can be configured to use only defined CA(s) for specific purposes. There is no default set of CA certificates included in the product.'
  desc 'check', 'Check that a signed certificate and CA certificate have been imported:

cli% showcert -service unified-server

If the output does not contain DOD PKI certificates of at least two lines of output, one of type "cert" and one of type "rootca", this is a finding.'
  desc 'fix', 'Create a CSR to be signed by an appropriate CA:

cli% createcert unified-server -csr -CN <common name> -SAN <DNS:somednsname or  IP:someipaddress>

Copy the output and give it to the CA for signing.

Install the root CA certificate bundle:

cli% importcert unified-server -ca stdin

Copy and paste the ca bundle contents as instructed.

Install the signed certificate from the ca:

cli% importcert unified-server stdin

Copy and paste the PEM format signed certificate contents as instructed.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58960r870178_chk'
  tag severity: 'medium'
  tag gid: 'V-255287'
  tag rid: 'SV-255287r870180_rule'
  tag stig_id: 'HP3P-33-004020'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-58904r870179_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
