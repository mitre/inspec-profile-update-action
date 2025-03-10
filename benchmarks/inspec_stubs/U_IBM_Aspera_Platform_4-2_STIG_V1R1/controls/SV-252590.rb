control 'SV-252590' do
  title 'IBM Aspera Faspex must be configured to use NIST FIPS-validated cryptography to protect the integrity of file transfers.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).

'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Ensure that encryption is required for all transfers by the IBM Aspera Faspex:

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege.
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section from the left menu.
- Scroll down to the "Encryption" section.
- Verify that the "Encrypt transfers" option is checked.

If the "Encrypt transfers" option is not checked, this is a finding.'
  desc 'fix', 'Configure the system to require encryption for all transfers by the IBM Aspera Faspex:

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege.
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section from the left menu.
- Scroll down to the "Encryption" section.
- Put a check in the "Encrypt transfers" check box.
- Select "Update" at the bottom of the page.'
  impact 0.7
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56046r817938_chk'
  tag severity: 'high'
  tag gid: 'V-252590'
  tag rid: 'SV-252590r817940_rule'
  tag stig_id: 'ASP4-FA-050260'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-55996r817939_fix'
  tag satisfies: ['SRG-NET-000063-ALG-000012', 'SRG-NET-000510-ALG-000025', 'SRG-NET-000510-ALG-000111']
  tag 'documentable'
  tag cci: ['CCI-001453', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-13 b']
end
