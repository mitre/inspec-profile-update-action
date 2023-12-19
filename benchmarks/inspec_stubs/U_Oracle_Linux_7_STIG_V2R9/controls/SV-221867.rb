control 'SV-221867' do
  title 'The Oracle Linux operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exists to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(Verify the operating system protects against or limits the effects of DoS attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.

# grep 'net.ipv4.tcp_invalid_ratelimit' /etc/sysctl.conf /etc/sysctl.d/*

/etc/sysctl.conf:net.ipv4.tcp_invalid_ratelimit = 500

If "net.ipv4.tcp_invalid_ratelimit" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out this is a finding.

Check that the operating system implements the value of the "tcp_invalid_ratelimit" variable with the following command:

# /sbin/sysctl -a | grep 'net.ipv4.tcp_invalid_ratelimit'
net.ipv4.tcp_invalid_ratelimit = 500

If "net.ipv4.tcp_invalid_ratelimit" has a value of "0", this is a finding.

If "net.ipv4.tcp_invalid_ratelimit" has a value greater than "1000" and is not documented with the Information System Security Officer (ISSO), this is a finding.)
  desc 'fix', 'Set the system to implement rate-limiting measures by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

net.ipv4.tcp_invalid_ratelimit = 500 

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23582r419673_chk'
  tag severity: 'medium'
  tag gid: 'V-221867'
  tag rid: 'SV-221867r853725_rule'
  tag stig_id: 'OL07-00-040510'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-23571r419674_fix'
  tag 'documentable'
  tag legacy: ['SV-108577', 'V-99473']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
