control 'SV-253943' do
  title 'The Juniper EX switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Determine if the network device obtains public key certificates from an appropriate certificate policy through an approved service provider.

Verify the certificate is signed by an approved CA via the "show security pki local-certificate" or "show security pki local-certificate detail" commands.

If the network device does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', 'Configure the network device to obtain its public key certificates from an appropriate certificate policy through an approved service provider. To view installed certificates:
show security pki (ca-certificate | local-certificate)

Generate a public/private keypair:
request security pki generate-key-pair type <ecdsa|rsa> size <bit size> certificate-id <name>
Note: ECDSA certificates support 256, 384, or 512 key sizes and RSA supports 1024, 2048, or 4096.

Generate a certificate signing request:
request security pki generate-certificate-request certificate-id <key name> digest <sha-1|sha-256|sha-384> domain-name <FQDN> ip-address <IPv4 address> ipv6-address <IPv6 address> subject <LDAP format>
Note: The subject is LDAP formatted. For example, "CN=switch-01,DC=example,DC=com,O=Company,OU=HR,L=Some City,ST=Some State,C=US". Not all key => value pairs are required but those used must match organizational policy.

After securely transferring the CSR to the certificate authority for signing, and securely transferring the certificate to the device, add the certificate:
request security pki local-certificate load filename <path/filename of certificate> certificate-id <key name>

The certificate can also be generated externally, with separate public and private key files, or a PKCS#12 package containing both certificate and private key. When importing externally generated certificate and private key, use the "key" directive to identify the path and filename of the private key. If the private key, or the PKCS#12 package, uses a passphrase, use the "passphrase" directive and provide the correct value.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57395r843860_chk'
  tag severity: 'medium'
  tag gid: 'V-253943'
  tag rid: 'SV-253943r879887_rule'
  tag stig_id: 'JUEX-NM-000660'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-57346r843861_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
