control 'SV-252616' do
  title 'The IBM Aspera High-Speed Transfer Endpoint must be configured to use NIST FIPS-validated cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).

'
  desc 'check', 'Ensure that FIPS compliance is required for all transfers by the IBM Aspera High-Speed Transfer Endpoint with the following command:

$ sudo /opt/aspera/bin/asuserdata -a | grep fips

 transfer_encryption_fips_mode: "true"

If results are blank or fips mode is reported as "false", this is a finding.'
  desc 'fix', 'For implementations using IBM Aspera High-Speed Transfer Endpoint, configure FIPS compliance criteria to all transfers by executing the following command:

$ sudo /opt/aspera/bin/asconfigurator -x "set_node_data;transfer_encryption_fips_mode,true"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.7
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56072r818016_chk'
  tag severity: 'high'
  tag gid: 'V-252616'
  tag rid: 'SV-252616r831518_rule'
  tag stig_id: 'ASP4-TE-030140'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-56022r818017_fix'
  tag satisfies: ['SRG-NET-000062-ALG-000011', 'SRG-NET-000063-ALG-000012', 'SRG-NET-000510-ALG-000025', 'SRG-NET-000510-ALG-000111']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'SC-13 b']
end
