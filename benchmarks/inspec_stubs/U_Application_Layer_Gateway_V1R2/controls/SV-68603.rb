control 'SV-68603' do
  title 'The ALG providing intermediary services for remote access communications traffic must use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'If the ALG does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS and webmail), this is not applicable.

Verify the ALG uses encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.

If the ALG does not use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the ALG to use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54357'
  tag rid: 'SV-68603r1_rule'
  tag stig_id: 'SRG-NET-000062-ALG-000011'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-59211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
