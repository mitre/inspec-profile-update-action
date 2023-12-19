control 'SV-30994' do
  title 'If a VPN is used in the AD implementation, the traffic must be inspected by the network Intrusion detection system (IDS).'
  desc 'To provide data confidentiality, a VPN is configured to encrypt the data being transported. While this protects the data, some implementations do not allow that data to be processed through an intrusion detection system (IDS) that could detect data from a compromised system or malicious client.

Further policy details:Replace the VPN solution or reconfigure it so that directory data is processed by a network or host-based intrusion detection system (IDS).'
  desc 'check', '1. Interview the site representative. Ask about the location of the domain controllers. 

2. If domain controllers are not located in multiple enclaves, then this check is not applicable.

3. If domain controllers are located in multiple enclaves and a VPN is not used, then this check is not applicable.

4. If domain controllers are located in multiple enclaves and a VPN is used, review the site network diagram(s) with the SA, NSO, or network reviewer as required to determine if the AD network traffic is visible to a network or host IDS.

5. If the AD network traffic is not visible to a network or host IDS, then this is a finding.'
  desc 'fix', 'Replace the VPN solution or reconfigure it so that directory data is inspected by a network or host-based IDS.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-14101r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8523'
  tag rid: 'SV-30994r3_rule'
  tag stig_id: 'DS00.4140_AD'
  tag gtitle: 'IDS Visibility of Directory VPN Data Transport'
  tag fix_id: 'F-27873r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'EBVC-1'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
