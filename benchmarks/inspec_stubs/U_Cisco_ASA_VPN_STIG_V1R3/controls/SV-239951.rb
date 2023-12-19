control 'SV-239951' do
  title 'The Cisco ASA must be configured to use Internet Key Exchange (IKE) for all IPsec security associations.'
  desc 'Without IKE, the Security Parameter Index (SPI) is manually specified for each security association. IKE peers will negotiate the encryption algorithm and authentication or hashing methods as well as generate the encryption keys.

An IPsec SA is established using either IKE or manual configuration. When using IKE, the security associations are established when needed and expire after a period of time or volume of traffic threshold. If manually configured, they are established as soon as the configuration is complete at both endpoints and they do not expire. When using IKE, the SPI for each security association is a pseudo-randomly derived number.

With manual configuration of the IPsec security association, both the cipher key and authentication key are static. Hence, if the keys are compromised, the traffic being protected by the current IPsec tunnel can be decrypted as well as traffic in any future tunnels established by this SA. Furthermore, the peers are not authenticated prior to establishing the SA, which could result in a rogue device establishing an IPsec SA with either of the VPN endpoints.

IKE provides primary authentication to verify the identity of the remote system before negotiation begins. This feature is lost when the IPsec security associations are manually configured, which results in a non-terminating session using static pre-shared keys.'
  desc 'check', 'Step 1: Verify that IKE is configured for the IPsec Phase 1 policy and enabled on applicable interfaces.

crypto ikev2 policy 1
 encryption …

crypto ikev2 enable OUTSIDE

Step 2: Verify that IKE is configured for the IPsec Phase 2.

crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
 protocol esp encryption …

Note: Although IKEv2 is preferred, IKEv1 will meet the intent of this requirement.

If the IKE is not configured for all IPsec security associations, this is a finding.'
  desc 'fix', 'Configure the ASA to use IKE for all IPsec VPN SAs.

Step 1: Configure IKE for the IPsec Phase 1 policy and enable it on applicable interfaces.

ASA1(config)# crypto ikev2 policy 1
ASA1(config-ikev2-policy)# encryption …

ASA1(config)# crypto ikev2 enable OUTSIDE

Step 2: Configure IKE for the IPsec Phase 2.
 
ASA1(config)# crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43184r666257_chk'
  tag severity: 'high'
  tag gid: 'V-239951'
  tag rid: 'SV-239951r666259_rule'
  tag stig_id: 'CASA-VN-000150'
  tag gtitle: 'SRG-NET-000512-VPN-002220'
  tag fix_id: 'F-43143r666258_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
