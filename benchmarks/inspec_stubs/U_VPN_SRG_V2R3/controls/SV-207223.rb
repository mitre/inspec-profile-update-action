control 'SV-207223' do
  title 'The IPsec VPN Gateway must use Internet Key Exchange (IKE) with SHA-1 or greater to protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions. For digital signature verification, SHA-1 is allowed for legacy-use. For all other hash function applications (e.g., HMAC, KDFs, RBG, password hashing, checksum integrity checks), the use of SHA-1 is acceptable, but discouraged in DoD. 

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).

An IPsec Security Associations (SA) is established using either IKE or manual configuration.'
  desc 'check', 'Verify the IPsec VPN Gateway uses IKE with SHA1 or greater to protect the authenticity of communications sessions.

If the IPsec VPN Gateway is not configured to use IKE with SHA1 or greater to protect the authenticity of communications sessions, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to use IKE with SHA1 or greater to protect the authenticity of communications sessions.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7483r378290_chk'
  tag severity: 'high'
  tag gid: 'V-207223'
  tag rid: 'SV-207223r608988_rule'
  tag stig_id: 'SRG-NET-000230-VPN-000780'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-7483r378291_fix'
  tag 'documentable'
  tag legacy: ['SV-106263', 'V-97125']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
