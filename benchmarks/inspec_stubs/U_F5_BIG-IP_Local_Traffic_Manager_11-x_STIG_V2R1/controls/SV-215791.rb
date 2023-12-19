control 'SV-215791' do
  title 'The BIG-IP Core implementation must be configured to implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks to virtual servers.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy; which service redundancy reduces the susceptibility of the ALG to many DoS attacks.

The ALG must be configured to prevent or mitigate the impact on network availability and traffic flow of DoS attacks that have occurred or are ongoing.

This requirement applies to the functionality of the device as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technologies, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.'
  desc 'check', 'Verify the BIG-IP Core implements load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.

Navigate to the BIG-IP System manager >> System >> Configuration >> Local Traffic >> General.

Verify "Reaper High-water Mark" is set to 95 and "Reaper Low-water Mark" is set to 85.

If the device does not implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks, this is a finding.'
  desc 'fix', 'Configure the BIG-IP Core to implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.

Navigate to the BIG-IP System manager >> System >> Configuration >> Local Traffic >> General.

Make the following configurations under "Properties".

Set "Reaper High-water Mark" to 95.

Set "Reaper Low-water Mark" to 85.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16983r291186_chk'
  tag severity: 'high'
  tag gid: 'V-215791'
  tag rid: 'SV-215791r557356_rule'
  tag stig_id: 'F5BI-LT-000217'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-16981r291187_fix'
  tag 'documentable'
  tag legacy: ['SV-74793', 'V-60363']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
