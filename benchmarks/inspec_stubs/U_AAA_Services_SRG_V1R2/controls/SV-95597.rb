control 'SV-95597' do
  title 'AAA Services must be configured to use their loopback or OOB management interface address as the source address when originating NTP traffic.'
  desc "Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. NTP provides an efficient and scalable method for network devices to synchronize to an accurate time source.

Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router's loopback address instead of the numerous physical interface addresses. NTP messages sent to management servers should use the loopback address as the source address."
  desc 'check', 'Verify AAA Services are configured to use their loopback interface address as the source address when originating NTP traffic. When AAA Services are managed from an OOB management network, the OOB interface must be used instead of the loopback address for originating NTP traffic.

If AAA Services are not configured to use the OOB interface when managed from an OOB management network, this is a finding.

If AAA Services are not configured to use the loopback or OOB management interface as the source address when originating NTP traffic, this is a finding.'
  desc 'fix', 'Configure AAA Services to use their loopback or OOB management interface address as the source address when originating NTP traffic.'
  impact 0.3
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80625r1_chk'
  tag severity: 'low'
  tag gid: 'V-80887'
  tag rid: 'SV-95597r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000370'
  tag gtitle: 'SRG-APP-000516-AAA-000370'
  tag fix_id: 'F-87743r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
