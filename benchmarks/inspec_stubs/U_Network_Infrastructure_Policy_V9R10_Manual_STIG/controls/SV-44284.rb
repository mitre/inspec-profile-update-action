control 'SV-44284' do
  title 'A policy must be implemented to keep Bogon/Martian rulesets up to date.'
  desc 'A Bogon route or Martian address is a type of packet that should never be routed inbound through the perimeter device.  Bogon routes and Martian addresses are commonly found as the source addresses of DDoS attacks.  By not having a policy implemented to keep these addresses up to date, the enclave will run the risk of allowing illegitimate traffic into the enclave or even blocking legitimate traffic.  Also, if there are rulesets with "any" as the source address then Bogons/Martians must be applied.

Bogons and Martian addresses can be kept up to date routinely checking the IANA website or creating an account with Team Cymru to retrieve these lists in one of many ways.

http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xml
http://www.team-cymru.org/Services/Bogons/'
  desc 'check', 'Review the Bogon/Martian maintenance policy to validate plans and procedures are in place to protect the enclave from illegitimate network traffic with up to date Bogon/Martian rulesets. 

If the site does not have a policy to keep Bogon/Martian rulesets up to date, this is a finding.'
  desc 'fix', 'Implement a Bogon/Martian maintenance policy to protect the enclave from illegitimate network traffic.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-41894r5_chk'
  tag severity: 'medium'
  tag gid: 'V-33831'
  tag rid: 'SV-44284r2_rule'
  tag stig_id: 'NET0928'
  tag gtitle: 'NET0928 - Bogon/Martian policy established'
  tag fix_id: 'F-37761r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Network Security Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
