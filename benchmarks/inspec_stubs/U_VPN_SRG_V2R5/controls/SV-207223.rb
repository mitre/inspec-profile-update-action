control 'SV-207223' do
  title 'The IPSec VPN must be configured to use FIPS-validated SHA-2 at 384 bits or higher for Internet Key Exchange (IKE).'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DOD systems should not be configured to use SHA-2 for integrity of remote access sessions.

This requirement is applicable to the configuration of IKE Phase 1 and Phase 2.'
  desc 'check', 'Verify the IPsec VPN Gateway uses IKE with SHA-2 at 384 bits or greater to protect the authenticity of communications sessions.

If the IPsec VPN Gateway is not configured to use IKE with SHA-2 at 384 bits or greater to protect the authenticity of communications sessions, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to use IKE with SHA-2 at 384 bits or greater to protect the authenticity of communications sessions.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7483r916150_chk'
  tag severity: 'high'
  tag gid: 'V-207223'
  tag rid: 'SV-207223r916152_rule'
  tag stig_id: 'SRG-NET-000230-VPN-000780'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-7483r916151_fix'
  tag 'documentable'
  tag legacy: ['SV-106263', 'V-97125']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
