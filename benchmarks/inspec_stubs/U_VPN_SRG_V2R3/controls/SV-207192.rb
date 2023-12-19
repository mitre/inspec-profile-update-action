control 'SV-207192' do
  title 'The VPN Gateway must be configured to use IPsec with SHA-1 or greater for hashing to protect the integrity of remote access sessions.'
  desc 'Without strong cryptographic integrity protections, information can be altered by unauthorized users without detection.

Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. For digital signature verification, SHA-1 is allowed for legacy-use. For all other hash function applications (e.g., HMAC, KDFs, RBG, password hashing, checksum integrity checks), the use of SHA-1 is acceptable, but discouraged in DoD. 

The remote access VPN provides access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.'
  desc 'check', 'Verify the VPN Gateway uses IPsec with SHA-1 or greater for hashing to protect the integrity of remote access sessions.

If the VPN Gateway does not use IPsec with SHA-1 or greater for hashing to protect the integrity of remote access sessions, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to use IPsec with SHA-1 or greater for hashing to protect the integrity of remote access sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7452r378197_chk'
  tag severity: 'medium'
  tag gid: 'V-207192'
  tag rid: 'SV-207192r608988_rule'
  tag stig_id: 'SRG-NET-000063-VPN-000220'
  tag gtitle: 'SRG-NET-000063'
  tag fix_id: 'F-7452r378198_fix'
  tag 'documentable'
  tag legacy: ['SV-106195', 'V-97057']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
