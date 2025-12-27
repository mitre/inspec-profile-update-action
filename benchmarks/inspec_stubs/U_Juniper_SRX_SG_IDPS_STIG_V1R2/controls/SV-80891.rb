control 'SV-80891' do
  title 'The Juniper Networks SRX Series Gateway IDPS must block outbound traffic containing known and unknown DoS attacks by ensuring that anomaly-based attack objects are applied to outbound communications traffic.'
  desc 'The IDPS must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. 

To perform anomaly-based attacks on the Juniper SRX IDPS device, create an anomaly-based attack object.'
  desc 'check', 'From operational mode, enter the following command to verify that the anomaly-based attack object was created. 

show idp security policies

If anomaly-based attack objects are not created, bound to a zone, and active, this is a finding.'
  desc 'fix', 'Create a protocol anomaly-based attack object:

Specify a name for the attack.
[edit]
security idp custom-attack anomaly1

Specify common properties for the attack.
[edit security idp custom-attack anomaly1]
set severity info
set time-binding scope peer count 2

Specify the attack type and test condition.
[edit] 
security idp custom-attack anomaly1
set attack-type anomaly test OPTIONS_UNSUPPORTED

Specify other properties for the anomaly attack.
[edit]
security idp custom-attack anomaly1
set attack-type anomaly service TCP
u set attack-type anomaly direction any
attack-type anomaly shellcode spark'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67047r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66401'
  tag rid: 'SV-80891r1_rule'
  tag stig_id: 'JUSX-IP-000007'
  tag gtitle: 'SRG-NET-000192-IDPS-00140'
  tag fix_id: 'F-72477r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
