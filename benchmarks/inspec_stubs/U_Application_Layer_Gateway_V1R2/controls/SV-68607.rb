control 'SV-68607' do
  title 'The ALG providing intermediary services for remote access communications traffic must use NIST FIPS-validated cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'If the ALG does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS and webmail), this is not applicable.

Verify the ALG uses cryptography to protect the integrity of remote access sessions.

If the ALG does not use cryptography to protect the integrity of remote access sessions, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the ALG to use cryptography to protect the integrity of remote access sessions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54361'
  tag rid: 'SV-68607r1_rule'
  tag stig_id: 'SRG-NET-000063-ALG-000012'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-59215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
