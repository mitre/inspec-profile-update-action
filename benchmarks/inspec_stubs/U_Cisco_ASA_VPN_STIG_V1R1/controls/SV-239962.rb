control 'SV-239962' do
  title 'The Cisco ASA VPN gateway must use cryptographic algorithms approved by NSA to protect NSS when transporting classified traffic across an unclassified network.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VPN gateway must implement cryptographic modules adhering to the higher standards approved by the Federal Government since this provides assurance they have been tested and validated.

NIST cryptographic algorithms are approved by NSA to protect NSS. Based on an analysis of the impact of quantum computing, cryptographic algorithms specified by CNSSP-15 and approved for use in products in the CSfC program have been changed to more stringent protocols and configured with increased bit sizes and other secure characteristics to protect against quantum computing threats. The Commercial National Security Algorithm Suite (CNSA Suite) replaces Suite B.'
  desc 'check', 'Verify the VPN gateway is configured to use cryptography that is compliant with CSNA/CNSSP when transporting classified traffic across an unclassified network.

Step 1: Verify CSNA/CNSSP-15 parameters have been configured for IKE Phase 1 as shown in the example below.
 
crypto ikev2 policy 2
 encryption aes-256
 integrity null
 group 19
 prf sha384

Step 2: Determine the crypto map for IKE Phase 2 used in compliance with CSNA/CNSSP-15.

crypto map CSNA_MAP 10 set ikev2 ipsec-proposal aes-256

Step 3: Verify the proposal specifies AES 256 parameters.

crypto ipsec ikev2 ipsec-proposal AES-256
 protocol esp encryption aes-256

If the VPN gateway is not configured to use cryptography that is compliant with CSNA/CNSSP-15 parameters when transporting classified traffic across an unclassified network, this is a finding.'
  desc 'fix', 'Configure the VPN gateway to use cryptography that is compliant with CSNA/CNSSP-15 parameters when transporting classified traffic across an unclassified network as shown in the example below.

Step 1: Configure the IKE Phase 1.

ASA2(config)# crypto ikev2 policy 2
ASA2(config-ikev2-policy)# encryption aes-256
ASA2(config-ikev2-policy)# integrity null
ASA2(config-ikev2-policy)# group 20
ASA2(config-ikev2-policy)# prf sha384
ASA2(config-ikev2-policy)# exit

Step 2: Configure the IPsec proposal for AES 256 and apply to a crypto map as shown in the example below.

ASA2(config-ipsec-proposal)# protocol esp encryption aes-256
ASA2(config-ipsec-proposal)# exit
ASA2(config)# crypto map CSNA_MAP 10 set ikev2 ipsec-proposal AES-256
ASA2(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43195r792461_chk'
  tag severity: 'high'
  tag gid: 'V-239962'
  tag rid: 'SV-239962r792463_rule'
  tag stig_id: 'CASA-VN-000340'
  tag gtitle: 'SRG-NET-000565-VPN-002400'
  tag fix_id: 'F-43154r792462_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
