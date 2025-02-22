control 'SV-252591' do
  title 'IBM Aspera Faspex must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify the IBM Aspera Faspex implements cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege.
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section from the left menu.
- Scroll down to the "Encryption" section.
- Verify that the "Use encryption-at-rest" radio button is set to "Always".

If the "Use encryption-at-rest" radio button is set to "Never" or "Optional", this is a finding.'
  desc 'fix', 'Configure the IBM Aspera Faspex to implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege.
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section from the left menu.
- Scroll down to the "Encryption" section.
- Select the "Use encryption-at-rest" radio button "Always".
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56047r817941_chk'
  tag severity: 'medium'
  tag gid: 'V-252591'
  tag rid: 'SV-252591r817943_rule'
  tag stig_id: 'ASP4-FA-050270'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55997r817942_fix'
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
