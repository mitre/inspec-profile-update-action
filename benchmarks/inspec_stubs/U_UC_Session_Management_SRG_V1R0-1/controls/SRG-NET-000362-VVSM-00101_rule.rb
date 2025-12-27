control 'SRG-NET-000362-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to protect against or limit the effects of all types of denial-of-service (DoS) attacks by employing organizationally defined security safeguards.'
  desc 'A network element experiencing a DoS attack will not be able to handle the traffic load. The high CPU utilization caused by a DoS attack will also have impact control keep-alives and timers used for neighbor peering, resulting in route flapping and eventually black hole traffic.

The network element must be configured to prevent or mitigate the impact on network availability and traffic flow of DoS attacks that have occurred or are ongoing. A variety of technologies and functionality can be leveraged to limit or, in some cases, eliminate the effects of DoS attacks (e.g., load balancing and access control lists). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks. 

This requirement applies to the network traffic functionality of the network element as it pertains to handling network traffic. Some types of attacks may be specialized to certain network technology, functions, or services. For each technology, known and potential DoS attacks must be identified and solutions for each type implemented.'
  desc 'check', 'Verify the Unified Communications Session Manager is configured to protect against or limit all types of DoS attacks.

If the Unified Communications Session Manager is not configured to protect against or limit all types of denial-of-service (DoS) attacks, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to protect against or limit all types of DoS attacks.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000362-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000362-VVSM-00101'
  tag rid: 'SRG-NET-000362-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000362-VVSM-00101'
  tag gtitle: 'SRG-NET-000362-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000362-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
