control 'SV-239985' do
  title 'The Cisco ASA VPN remote access server must be configured to use an approved High Assurance Commercial Solution for Classified (CSfC) cryptographic algorithm for remote access to a classified network.'
  desc "Use of improperly configured or lower assurance equipment and solutions could compromise high-value information.

The National Security Agency/Central Security Service's (NSA/CSS) CSfC program enables commercial products to be used in layered solutions to protect classified National Security Systems (NSS) data. Based on an analysis of the impact of quantum computing, cryptographic algorithms specified by CNSSP-15 and approved for use in products in the CSfC program have been changed to more stringent protocols and configured with increased bit sizes and other secure characteristics to protect against quantum computing threats. The Commercial National Security Algorithm Suite (CNSA Suite) replaces Suite B."
  desc 'check', 'Verify the ASA uses an approved High Assurance CSfC cryptographic algorithm for remote access to a classified network.

Step 1: Verify IKE Phase 1 is configured in compliance with CSNA/CNSSP-15 parameters as shown in the example below.
 
crypto ikev2 policy 2
 encryption aes-256
 integrity null
 group 19
 prf sha384

Step 2: Determine the crypto map for IKE Phase 2 used is in compliance with CSNA/CNSSP-15 as in the example below.

crypto map CSNA_MAP 10 set ikev2 ipsec-proposal AES-256

Step 3: Verify the proposal specifies CSNA/CNSSP-15 parameters.

crypto ipsec ikev2 ipsec-proposal AES-256
 protocol esp encryption aes-256

If the ASA is not configured to use an approved High Assurance CSfC cryptographic algorithm for remote access to a classified network, this is a finding.'
  desc 'fix', 'Configure the ASA to use an approved High Assurance CSfC cryptographic algorithm for remote access to a classified network.

Step 1: Configure the IKE Phase 1.

ASA2(config)# crypto ikev2 policy 2
ASA2(config-ikev2-policy)# encryption aes-256
ASA2(config-ikev2-policy)# integrity null
ASA2(config-ikev2-policy)# group 20
ASA2(config-ikev2-policy)# prf sha384
ASA2(config-ikev2-policy)# exit

Step 2: Configure the IPsec proposal in compliance with CNSA/CNSSP-15 and apply to a crypto map as shown in the example below.

ASA2(config-ipsec-proposal)# protocol esp encryption aes-256
ASA2(config-ipsec-proposal)# exit
ASA2(config)# crypto map CSNA_MAP 10 set ikev2 ipsec-proposal AES-256
ASA2(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43218r792464_chk'
  tag severity: 'high'
  tag gid: 'V-239985'
  tag rid: 'SV-239985r792466_rule'
  tag stig_id: 'CASA-VN-000760'
  tag gtitle: 'SRG-NET-000565-VPN-002390'
  tag fix_id: 'F-43177r792465_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
