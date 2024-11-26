control 'SV-255299' do
  title 'The HPE 3PAR OS must be configured to only use DOD PKI established certificate authorities for authentication in the establishment of protected sessions to the operating system with a centralized account management server.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

The DOD will only accept PKI certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

The HPE 3PAR OS can be configured to use only defined CA(s) for specific purposes. There is no default set of CA certificates included in the product.'
  desc 'check', 'Check that a signed client certificate and CA certificate have been imported for the ldap service:

cli% showcert -service ldap

If the output does not contain DOD PKI certificates of at least two lines of output, one of type "cert" and one of type "rootca", this is a finding.'
  desc 'fix', 'Create a CSR to be signed by an appropriate CA:

cli% createcert ldap -csr -CN <common name> -SAN <DNS:somednsname or IP:someipaddress>

Copy the output and give it to the CA for signing.

Install the root CA certificate bundle:

cli% importcert ldap -ca stdin
Copy and paste the ca bundle contents as instructed.

Install the signed certificate from the ca:
cli% importcert ldap stdin
Copy and paste the PEM format signed certificate contents as instructed.

The fipsvr process will be restarted.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58972r870214_chk'
  tag severity: 'medium'
  tag gid: 'V-255299'
  tag rid: 'SV-255299r870216_rule'
  tag stig_id: 'HP3P-33-134020'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-58916r870215_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
