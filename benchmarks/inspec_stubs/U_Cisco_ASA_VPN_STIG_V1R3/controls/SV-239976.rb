control 'SV-239976' do
  title 'The Cisco ASA remote access VPN server must be configured to use a FIPS-validated algorithm and hash function to protect the integrity of TLS remote access sessions.'
  desc 'Without integrity protection, unauthorized changes may be made to the log files and reliable forensic analysis and discovery of the source of malicious system activity may be degraded.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless.

Integrity checks include cryptographic checksums, digital signatures, or hash functions. Federal Information Processing Standard (FIPS) 186-4, Digital Signature Standard (DSS), specifies three NIST-approved algorithms: DSA, RSA, and ECDSA. All three are used to generate and verify digital signatures in conjunction with an approved hash function.'
  desc 'check', 'Verify the remote access ASA uses a FIPS-validated algorithms and hash function as shown in the example below.

ssl server-version tlsv1.2
ssl cipher tlsv1.2 fips

If the remote access ASA does not use a digital signature generated using FIPS-validated algorithms and hash function, this is a finding.'
  desc 'fix', 'Configure the remote access ASA to use a digital signature generated using FIPS-validated algorithms and an approved hash.

ASA1(config)# ssl cipher tlsv1.2 fips
ASA1(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43209r666332_chk'
  tag severity: 'medium'
  tag gid: 'V-239976'
  tag rid: 'SV-239976r769253_rule'
  tag stig_id: 'CASA-VN-000560'
  tag gtitle: 'SRG-NET-000063-VPN-000210'
  tag fix_id: 'F-43168r666333_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
