control 'SV-239958' do
  title 'The Cisco ASA must be configured to use FIPS-validated SHA-2 or higher for Internet Key Exchange (IKE) Phase 1.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and Government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-2 for integrity of remote access sessions.'
  desc 'check', 'Review the ASA configuration to verify that SHA-2 or higher is specified for IKE Phase 1 as shown in the example below.

crypto ikev2 policy 1
 …
 integrity sha256

If the ASA is not configured to use SHA-2 or higher for IKE Phase 1, this is a finding.'
  desc 'fix', 'Configure the ASA to use FIPS-validated SHA-2 or higher for IKE Phase 1 as shown in the example below.

ASA2(config)# crypto ikev2 policy 1
ASA2(config-ikev2-policy)# integrity sha256'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43191r769244_chk'
  tag severity: 'medium'
  tag gid: 'V-239958'
  tag rid: 'SV-239958r769246_rule'
  tag stig_id: 'CASA-VN-000230'
  tag gtitle: 'SRG-NET-000168-VPN-000600'
  tag fix_id: 'F-43150r769245_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
