control 'SV-95487' do
  title 'The SDN controller must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by rate-limiting control-plane communications.'
  desc 'The SDN Controller is critical to all network operations because it is the component used to build all forwarding paths for the data plane via control-plane processes. It is also instrumental with network management and provisioning functions that keep the SDN-enabled network elements and links available for providing network services. Any disruption to the SDN Controller can result in mission-critical network outages. A DoS attack targeting the SDN Controller can result in excessive CPU and memory utilization. The SDN Controller must be configured to rate-limit control-plane traffic destined to itself to mitigate the risk of a DoS attack and ensure network stability.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to rate-limit control-plane messages. 

If the SDN controller is not configured to rate-limit control-plane messages, this is a finding.'
  desc 'fix', 'Configure the SDN controller to rate-limit control-plane messages.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80513r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80777'
  tag rid: 'SV-95487r1_rule'
  tag stig_id: 'SRG-NET-000362-SDN-000720'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-87631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
