control 'SV-239978' do
  title 'The Cisco ASA remote access VPN server must be configured to use SHA-2 or greater for hashing to protect the integrity of IPsec remote access sessions.'
  desc 'Without strong cryptographic integrity protections, information can be altered by unauthorized users without detection.

SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and Government standards. DoD systems must not be configured to use SHA-1 for integrity of remote access sessions. 

The remote access VPN provides access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.'
  desc 'check', 'Verify the ASA SHA-2 or greater for hashing to protect the integrity of IPsec remote access sessions as shown in the example below.

Step 1: Verify that SHA-2 or greater is used for IKE Phase 1 as shown in the example below.
 
crypto ikev2 policy 1
…
…
…
 integrity sha256

Step 2: Verify that SHA-2 or greater is used for the IPsec Security Association.

crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
 protocol esp integrity sha-256

If the ASA does not use SHA-2 or greater for hashing to protect the integrity of IPsec remote access sessions, this is a finding.'
  desc 'fix', 'Configure the ASA to use SHA-2 or greater for hashing to protect the integrity of IPsec remote access sessions as shown in the example below.

ASA1(config)# crypto ikev2 policy 1
ASA1(config-ikev2-policy)# integrity sha256
ASA1(config-ikev2-policy)# exit
ASA1(config)# crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
ASA1(config-ipsec-proposal)# protocol esp integrity sha-256
ASA1(config-ikev2-policy)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43211r666338_chk'
  tag severity: 'medium'
  tag gid: 'V-239978'
  tag rid: 'SV-239978r769254_rule'
  tag stig_id: 'CASA-VN-000630'
  tag gtitle: 'SRG-NET-000063-VPN-000220'
  tag fix_id: 'F-43170r666339_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
