control 'SV-80889' do
  title 'The Juniper Networks SRX Series Gateway IDPS must block outbound traffic containing known and unknown DoS attacks by ensuring that signature-based objects are applied to outbound communications traffic.'
  desc 'The IDPS must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. 

To perform signature-based attacks on the Juniper SRX IDPS device, create a signature-based attack object.'
  desc 'check', 'From operational mode, enter the following command to verify that the signature-based attack object was created: 

show security idp policies

If signature-based attack objects are not created, bound to a zone, and active, this is a finding.'
  desc 'fix', 'Specify a name for the attack. Specify common properties for the attack. Specify the attack type and context. Specify the attack direction and the shellcode flag. Set the protocol and its fields. Specify the protocol binding and ports. Specify the direction.

[edit]
edit security idp custom-attack sig1
set severity major
set recommended-action drop-packet
set time-binding scope source count 10
set attack-type signature context packet
set attack-type signature <signature object name>
set attack-type signature protocol ip ttl value 128 match equal
set attack-type signature protocol-binding tcp minimum-port 50 maximum-port 100
set attack-type signature direction any'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67045r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66399'
  tag rid: 'SV-80889r1_rule'
  tag stig_id: 'JUSX-IP-000006'
  tag gtitle: 'SRG-NET-000192-IDPS-00140'
  tag fix_id: 'F-72475r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
