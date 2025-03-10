control 'SV-239959' do
  title 'The Cisco ASA must be configured to use FIPS-validated SHA-2 or higher for Internet Key Exchange (IKE) Phase 2.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and Government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-2 for integrity of remote access sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).

An IPsec Security Association (SA) is established using either IKE or manual configuration.'
  desc 'check', 'Review the ASA configuration to verify that SHA-2 or higher is specified for IKE Phase 2 as shown in the example below.

Step 1: Review the crypto map for IKE Phase 2.

crypto map IPSEC_MAP 10 set ikev2 ipsec-proposal AES_SHA

Step 2: Verify that the proposal specifies SHA-2 or higher.

crypto ipsec ikev2 ipsec-proposal AES_SHA
 protocol esp encryption …
 protocol esp integrity sha-384 sha-256

If the ASA is not configured to use SHA-2 or higher for IKE Phase 2, this is a finding.'
  desc 'fix', 'Configure the ASA to use FIPS-validated SHA-2 or higher for IKE Phase 2.

Step 1: Configure the IKE Phase 2 proposal as shown in the example below.

ASA1(config)# crypto ipsec ikev2 ipsec-proposal AES_SHA
ASA1(config-ipsec-proposal)# protocol esp integrity sha-384 sha-256
ASA1(config-ipsec-proposal)# exit

Step 2: Configure the crypto map using the configured proposal.

ASA1(config)# crypto map IPSEC_MAP 10 set ikev2 ipsec-proposal
ASA1(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43192r769247_chk'
  tag severity: 'high'
  tag gid: 'V-239959'
  tag rid: 'SV-239959r916152_rule'
  tag stig_id: 'CASA-VN-000240'
  tag gtitle: 'SRG-NET-000230-VPN-000780'
  tag fix_id: 'F-43151r769248_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
