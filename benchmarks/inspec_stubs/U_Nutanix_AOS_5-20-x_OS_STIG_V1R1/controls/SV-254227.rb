control 'SV-254227' do
  title 'Nutanix AOS must protect against or limit the effects of denial-of-service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(Confirm Nutanix AOS protects against or limits the effects of DoS attacks by ensuring that a rate-limiting measures are enabled.

$ /sbin/sysctl -a | grep 'net.ipv4.tcp_invalid_ratelimit'
net.ipv4.tcp_invalid_ratelimit = 500

If "net.ipv4.tcp_invalid_ratelimit" has a value of "0", this is a finding.

If "net.ipv4.tcp_invalid_ratelimit" has a value greater than "1000" and is not documented with the Information System Security Officer (ISSO), this is a finding.)
  desc 'fix', 'Configure Nutanix AOS firewall services by running the following command:

$ sudo salt-call state.sls security/CVM/iptables/init'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57712r846767_chk'
  tag severity: 'medium'
  tag gid: 'V-254227'
  tag rid: 'SV-254227r846769_rule'
  tag stig_id: 'NUTX-OS-001500'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-57663r846768_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
