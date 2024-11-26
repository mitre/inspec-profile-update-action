control 'SV-207191' do
  title 'The remote access VPN Gateway must use a digital signature generated using FIPS-validated algorithms and an approved hash function to protect the integrity of remote access sessions.'
  desc 'Without integrity protection, unauthorized changes may be made to the log files and reliable forensic analysis and discovery of the source of malicious system activity may be degraded.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless.

Integrity checks include cryptographic checksums, digital signatures, or hash functions. Federal Information Processing Standard (FIPS) 186-4, Digital Signature Standard (DSS), specifies three NIST-approved algorithms: DSA, RSA, and ECDSA. All three are used to generate and verify digital signatures in conjunction with an approved hash function.'
  desc 'check', 'Verify the remote access VPN Gateway uses a digital signature generated using FIPS-validated algorithms and an approved hash function to protect the integrity of remote access sessions.

If the remote access VPN Gateway does not use a digital signature generated using FIPS-validated algorithms and an approved hash function to protect the integrity of remote access sessions, this is a finding.'
  desc 'fix', 'Configure the remote access VPN Gateway to use a digital signature generated using FIPS-validated algorithms and an approved hash function to protect the integrity of remote access sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7451r378194_chk'
  tag severity: 'medium'
  tag gid: 'V-207191'
  tag rid: 'SV-207191r608988_rule'
  tag stig_id: 'SRG-NET-000063-VPN-000210'
  tag gtitle: 'SRG-NET-000063'
  tag fix_id: 'F-7451r378195_fix'
  tag 'documentable'
  tag legacy: ['V-97055', 'SV-106193']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
