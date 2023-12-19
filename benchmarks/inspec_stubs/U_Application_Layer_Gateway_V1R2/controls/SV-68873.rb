control 'SV-68873' do
  title 'The ALG must implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy; which service redundancy reduces the susceptibility of the ALG to many DoS attacks.

The ALG must be configured to prevent or mitigate the impact on network availability and traffic flow of DoS attacks that have occurred or are ongoing.

This requirement applies to the network traffic functionality of the device as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technologies, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.'
  desc 'check', 'Verify the ALG implements load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.

If the device does not implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks, this is a finding.'
  desc 'fix', 'Configure the ALG to implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54627'
  tag rid: 'SV-68873r1_rule'
  tag stig_id: 'SRG-NET-000362-ALG-000120'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-59483r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
