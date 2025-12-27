control 'SV-206693' do
  title 'The firewall implementation must manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks.'
  desc %q(A firewall experiencing a DoS attack will not be able to handle production traffic load. The high utilization and CPU caused by a DoS attack will also have an effect on control keep-alives and timers used for neighbor peering resulting in route flapping and will eventually black hole production traffic.

The device must be configured to contain and limit a DoS attack's effect on the device's resource utilization. The use of redundant components and load balancing are examples of mitigating "flood-type" DoS attacks through increased capacity.)
  desc 'check', 'Use the "show" command to verify that all inbound interfaces have a stateless firewall filter to set rate limits based on a destination.

If the firewall does not have a stateless firewall filter that sets rate limits based on a destination, this is a finding.'
  desc 'fix', 'Configure a stateless firewall filter to set rate limits based on a destination of the packets. Apply the stateless firewall filter to all inbound interfaces.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6950r297858_chk'
  tag severity: 'medium'
  tag gid: 'V-206693'
  tag rid: 'SV-206693r604133_rule'
  tag stig_id: 'SRG-NET-000193-FW-000030'
  tag gtitle: 'SRG-NET-000193'
  tag fix_id: 'F-6950r297859_fix'
  tag 'documentable'
  tag legacy: ['SV-94127', 'V-79421']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
