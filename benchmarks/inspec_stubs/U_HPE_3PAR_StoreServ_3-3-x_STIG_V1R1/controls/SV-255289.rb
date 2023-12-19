control 'SV-255289' do
  title 'The HPE 3PAR OS syslog-sec-client must be configured to perform mutual TLS authentication using a CA-signed client certificate.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DOD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DOD-approved CA, trust of this CA has not been established.

The DOD will only accept PKI-certificates obtained from a DOD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

The HPE 3PAR OS can be configured to use only defined CA(s) for specific purposes. There is no default set of CA certificates included in the product.'
  desc 'check', 'Check with the Information Owner to verify if Mutual Authentication is required by the syslog server.

If mutual TLS authentication is not required, this requirement is not applicable.

Check that a signed client certificate and CA certificate have been imported for the syslog-sec-client service:

cli% showcert -service syslog-sec-client

If the output does not contain DOD PKI certificates of at least two lines of output, one of type "cert" and one of type "rootca", this is a finding.'
  desc 'fix', 'Check with the Information Owner to verify that TLS mutual authentication is required by the remote syslog server.

If TLS mutual authentication is not required, this requirement is not applicable.

Create a CSR to be signed by an appropriate CA:

cli% createcert syslog-sec-client -csr -CN <common name> -SAN <DNS:somednsname or IP:someipaddress>

Copy the output and give it to the CA for signing.

Install the root CA certificate bundle:

cli% importcert syslog-sec-client -ca stdin

Copy and paste the ca bundle contents as instructed.

Install the signed certificate from the ca:

cli% importcert sysloc-sec-client stdin

Copy and paste the PEM format signed certificate contents as instructed.

The syslog-sec-client service will be restarted.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58962r870184_chk'
  tag severity: 'medium'
  tag gid: 'V-255289'
  tag rid: 'SV-255289r870186_rule'
  tag stig_id: 'HP3P-33-104020'
  tag gtitle: 'SRG-OS-000403-GPOS-00182'
  tag fix_id: 'F-58906r870185_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
