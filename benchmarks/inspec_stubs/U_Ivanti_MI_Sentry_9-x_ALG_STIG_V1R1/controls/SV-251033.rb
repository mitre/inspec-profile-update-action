control 'SV-251033' do
  title 'The Sentry must implement load balancing to limit the effects of known and unknown types of Denial-of-Service (DoS) attacks.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy; which service redundancy reduces the susceptibility of the ALG to many DoS attacks.

The ALG must be configured to prevent or mitigate the impact on network availability and traffic flow of DoS attacks that have occurred or are ongoing.

This requirement applies to the network traffic functionality of the device as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technologies, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.'
  desc 'check', 'Verify the Sentry is implemented behind a load balancer to limit the effects of known and unknown types of DoS attacks.

If the device is not implemented behind a load balancer to limit the effects of known and unknown types of DoS attacks, this is a finding.'
  desc 'fix', 'Configure the Sentry to be implemented behind a load balancer to limit the effects of known and unknown types of DoS attacks.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54468r802319_chk'
  tag severity: 'low'
  tag gid: 'V-251033'
  tag rid: 'SV-251033r802321_rule'
  tag stig_id: 'MOIS-AL-000970'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-54422r802320_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
