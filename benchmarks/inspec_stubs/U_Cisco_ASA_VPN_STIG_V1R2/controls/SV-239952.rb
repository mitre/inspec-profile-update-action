control 'SV-239952' do
  title 'The Cisco ASA must be configured to use Internet Key Exchange v2 (IKEv2) for all IPsec security associations.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Use of IKEv2 leverages DoS protections because of improved bandwidth management and leverages more secure encryption algorithms.'
  desc 'check', 'Verify the ASA is configured to use IKEv2 for IPsec VPN security associations.

Step 1: Verify that IKE is configured for the IPsec Phase 1 policy and enabled on applicable interfaces.

crypto ikev2 policy 1
 encryption …

crypto ikev2 enable OUTSIDE

Step 2: Verify that IKE is configured for the IPsec Phase 2.

crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
 protocol esp encryption …

If the ASA is not configured to use IKEv2 for all IPsec VPN security associations, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to use IKEv2 for all IPsec VPN Security Associations.

Step 1: Configure IKE for the IPsec Phase 1 policy and enable it on applicable interfaces.

ASA1(config)# crypto ikev2 policy 1
ASA1(config-ikev2-policy)# encryption …

ASA1(config)# crypto ikev2 enable OUTSIDE

Step 2: Configure IKE for the IPsec Phase 2.

ASA1(config)# crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43185r666260_chk'
  tag severity: 'medium'
  tag gid: 'V-239952'
  tag rid: 'SV-239952r666262_rule'
  tag stig_id: 'CASA-VN-000160'
  tag gtitle: 'SRG-NET-000132-VPN-000460'
  tag fix_id: 'F-43144r666261_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
