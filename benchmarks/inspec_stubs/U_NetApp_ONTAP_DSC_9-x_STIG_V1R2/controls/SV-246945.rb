control 'SV-246945' do
  title 'ONTAP must use DoD-approved PKI rather than proprietary or self-signed device certificates.'
  desc 'Each organization obtains user certificates from an approved, shared service provider as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority (CA) at medium assurance or higher, this CA will suffice.'
  desc 'check', 'Use the command "security certificate show -instance -type client-ca" to show information about the ca-certificates that are installed.

If any of the certificates have the name or identifier of a non-approved source in the Issuer field, this is a finding.'
  desc 'fix', 'Generate a new key-pair from a DoD-approved certificate issuer. Sites must consult the PKI/PKI pages on the http://iase.disa.mil/ website for procedures for NIPRNet and SIPRNet.

RSA:
request security pki generate-key-pair certificate-id <cert name> type rsa size <512 | 1024 | 2048 | 4096>

ECDSA:
request security pki generate-key-pair certificate-id <cert_name> type ecdsa size <256 | 384>

Generate a CSR from RSA key-pair using the following command and options.

request security generate-certificate-request certificate-id <cert_name_from_key_file> digest <sha1 | sha256> domain <FQDN> email <admin_email> ip-address <ip_address> subject “CN=<hostname>,DC=<domain_part>,DC=<TLD_domain>,O=<organization>,OU=<organization_dept>,
L=<city>,ST=<state>,C=<us>” filename <path/filename>

Generate a CSR from ECDSA key-pair use the following command and options.

request security generate-certificate-request certificate-id <cert_name_from_key_file> digest <sha256 | sha384> domain <FQDN> email <admin_email> ip-address <ip_address> subject “CN=<hostname>,DC=<domain_part>,DC=<TLD_domain>,O=<organization>,OU=<organization_dept>,
L=<city>,ST=<state>,C=<us>” filename <path/filename>

If no filename is specified, the CSR is displayed on the standard out (terminal)

After receiving the approved certificate from the CA, install the certificate with the command "security certificate install -type client-ca -vserver <vserver_name>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50377r835242_chk'
  tag severity: 'medium'
  tag gid: 'V-246945'
  tag rid: 'SV-246945r835244_rule'
  tag stig_id: 'NAOT-CM-000008'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-50331r835243_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
