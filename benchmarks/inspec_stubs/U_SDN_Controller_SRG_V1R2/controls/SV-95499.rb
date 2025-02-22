control 'SV-95499' do
  title 'The SDN controller must be configured to authenticate received southbound Application Program Interface (API) management-plane messages using a FIPS-approved message authentication code algorithm.'
  desc 'The SDN controller can receive management-plane traffic from the SDN-enabled devices that it monitors and manages. The messages could be responses from SNMP get requests as well as SNMP notifications (i.e., traps and informs) provided to note changes in node or link state. NETCONF is also used by the SDN controller to configure SDN-enabled devices as well as to receive state and configuration information. Communication between the SDN controller and NETCONF-enabled devices is session based. A session is established for the purpose of exchanging data using remote procedure call (RPC) requests and replies. If the SDN controller were to receive messages from a rogue device using SNMP or NETCONF providing fraud state information or configuration data, the abstract view of the network topology could be altered thereby providing an attacker with the ability to force traffic to bypass security controls or be forwarded using non-optimized paths. To ensure the integrity and authenticity of these messages, it is imperative that they are authenticated prior to processing and taking any action.'
  desc 'check', 'Review the SDN configuration, verify that it is configured to authenticate received southbound API management-plane messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the cipher-based message authentication code (CMAC) and the keyed-hash message authentication code (HMAC). AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. 

If the SDN controller is not configured to authenticate received southbound API management-plane messages using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Configure the SDN controller to authenticate southbound API management-plane messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the CMAC and the HMAC. AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.'
  impact 0.7
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80525r1_chk'
  tag severity: 'high'
  tag gid: 'V-80789'
  tag rid: 'SV-95499r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001040'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87643r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
