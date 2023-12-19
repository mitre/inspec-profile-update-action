control 'SV-252607' do
  title 'IBM Aspera Shares feature must be configured to use NIST FIPS-validated cryptography to protect the integrity of file transfers.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).

'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Ensure that encryption is required for all transfers by the IBM Aspera Shares:

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "System Settings" section.
- Select the "Transfers" option.
- Verify the "Encryption" option is set to at least "AES-128".

If the "Encryption" option is set to "optional" or not set, this is a finding.'
  desc 'fix', 'Configure the system to require encryption for all transfers by the IBM Aspera Shares:

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "System Settings" section.
- Select the "Transfers" option.
- Select an encryption level from the dropdown menu of "Encryption" of "AES-128" or greater.
- Select "Save" at the bottom of the page.'
  impact 0.7
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56063r817989_chk'
  tag severity: 'high'
  tag gid: 'V-252607'
  tag rid: 'SV-252607r831513_rule'
  tag stig_id: 'ASP4-SH-060200'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-56013r817990_fix'
  tag satisfies: ['SRG-NET-000063-ALG-000012', 'SRG-NET-000510-ALG-000025', 'SRG-NET-000510-ALG-000111']
  tag 'documentable'
  tag cci: ['CCI-001453', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-13 b']
end
