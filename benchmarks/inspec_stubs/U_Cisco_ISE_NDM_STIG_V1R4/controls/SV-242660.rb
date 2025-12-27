control 'SV-242660' do
  title 'The Cisco ISE must configure the control plane to protect against or limit the effects of common types of Denial of Service (DoS) attacks on the device itself by configuring applicable system options and internet-options.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Verify the system and system-options are configured to protect against DoS attacks.

If the system and system-options that limit the effects of common types of DoS attacks are not configured in compliance with DoD requirements, this is a finding.'
  desc 'fix', 'Configure the system and system-options to protect against DoS attacks. These are examples of setting that should be adjusted to limit DoS attacks. The exact values will vary based on site traffic.

Use the synflood-limit to configure a TCP SYN packet rate limit.

To configure the limit of TCP/UDP/ICMP packets from a source IP address, use the rate-limit command in configuration mode.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45935r714288_chk'
  tag severity: 'medium'
  tag gid: 'V-242660'
  tag rid: 'SV-242660r851071_rule'
  tag stig_id: 'CSCO-NM-000550'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-45892r714289_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
