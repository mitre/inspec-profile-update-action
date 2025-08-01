control 'SV-95501' do
  title 'The SDN controller must be configured to encrypt all southbound Application Program Interface (API) management-plane messages using a FIPS-validated cryptographic module.'
  desc 'An SDN controller can manage and configure SDN-enabled devices using protocols such as SNMP and NETCONF. If an SDN-aware router or switch received erroneous configuration information that was altered by a malicious user, interfaces could be disabled, erroneous IP addresses configured, services removed—all resulting a network disruption or even an outage.  Hence, it is imperative to secure the management plane by encrypting all southbound API management-plane traffic or deploying an out-of-band network for this traffic to traverse.'
  desc 'check', "Determine if the southbound API management-plane traffic traverses an out-of-band path. If not, review the SDN controller configuration to verify that southbound API management-plane traffic is encrypted using a using a FIPS-validated cryptographic module. 

If the southbound API management-plane traffic does not traverse an out-of-band path and is not encrypted using a FIPS-validated cryptographic module, this is a finding.

Note: FIPS-validated cryptographic modules are listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  desc 'fix', "Deploy an out-of-band network to provision paths between SDN controller and SDN-enabled devices as well as all hypervisor hosts that compose the SDN infrastructure to provide transport for southbound API management-plane traffic. 

An alternative is to configure the SDN controller to encrypt all southbound API management-plane traffic using a FIPS-validated cryptographic module. Implement a cryptographic module which has a validation certification and is listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  impact 0.7
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80527r2_chk'
  tag severity: 'high'
  tag gid: 'V-80791'
  tag rid: 'SV-95501r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001045'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
