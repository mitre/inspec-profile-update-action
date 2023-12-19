control 'SV-215399' do
  title 'AIX must protect against or limit the effects of Denial of Service (DoS) attacks by ensuring AIX is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of AIX to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Check to see if bos.net.tcp.client_core package is installed:

# lslpp -l | grep bos.net.tcp.client_core
bos.net.tcp.client_core    7.2.1.1  COMMITTED  TCP/IP Client Core Support
bos.net.tcp.client_core    7.2.1.1  COMMITTED  TCP/IP Client Core Support

If the packages are not "COMMITTED", this is a finding.

Check that the value set for "clean_partial_conns" is "1":

# /usr/sbin/no -o clean_partial_conns 
clean_partial_conns = 1

If the value returned is "0", this is a finding.'
  desc 'fix', 'Make sure "bos.net.tcp.client_core" package is installed on the system. 

Set the Network performance tuning attribute value for "clean_partial_connections to "1" to avoid SYN attacks.
# /usr/sbin/no -o clean_partial_conns=1'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16597r294648_chk'
  tag severity: 'medium'
  tag gid: 'V-215399'
  tag rid: 'SV-215399r853488_rule'
  tag stig_id: 'AIX7-00-003097'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-16595r294649_fix'
  tag 'documentable'
  tag legacy: ['SV-101657', 'V-91559']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
