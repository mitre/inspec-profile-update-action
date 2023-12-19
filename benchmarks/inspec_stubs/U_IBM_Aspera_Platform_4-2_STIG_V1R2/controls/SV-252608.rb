control 'SV-252608' do
  title 'IBM Aspera Shares must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify the IBM Aspera Shares implements cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "System Settings" section.
- Select the "Transfers" option.
- Verify the "Encryption at rest" option is set to "Required".

If the "Encryption at rest" option is set to "Optional" or is not set, this is a finding.'
  desc 'fix', 'Configure the IBM Aspera Shares to implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "System Settings" section.
- Select the "Transfers" option.
- Select the "Encryption at rest" option "Required".
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56064r817992_chk'
  tag severity: 'medium'
  tag gid: 'V-252608'
  tag rid: 'SV-252608r831514_rule'
  tag stig_id: 'ASP4-SH-060210'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56014r817993_fix'
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
