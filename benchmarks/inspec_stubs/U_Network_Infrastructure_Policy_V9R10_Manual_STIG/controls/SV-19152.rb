control 'SV-19152' do
  title 'Two Network Time Protocol (NTP) servers must be deployed in the management network.'
  desc 'NTP provides an efficient and scalable method for managed network elements to actively synchronize to an accurate time source. Insuring that there are always NTP servers available to provide time is critical. It is imperative that all single points of failure for the NTP infrastructure are eliminated. Knowing the correct time is not only crucial for proper network functioning but also for security. Compromising an NTP server opens the door to more sophisticated attacks that include NTP poisoning, replay attacks, and denial of service. 

Where possible, deploy multiple gateways with diverse paths to the NTP servers. An alternative design is to have one server connected to a reference clock and the other server reference an external stratum-1 server. With this scenario, the NTP clients should be configured to prefer the stratum-1 server over the stratum-2 server.

The NTP servers should be configured to easily scale by creating a hierarchy of lower level (stratum-2 to stratum-15) servers to accommodate the workload. The width and depth of the hierarchy is dependent on the number of NTP clients as well as the amount of redundancy that is required.'
  desc 'check', 'Review the network topology to determine that there are two NTP servers and what network they are connected to.  Verify that they are both online according to the documented IP address. 

Where possible, deploy multiple gateways with diverse paths to the NTP servers. An alternative design is to have one server connected to a reference clock and the other server reference an external stratum-1 server. With this scenario, the NTP clients should be configured to prefer the stratum-1 server over the stratum-2 server.

The NTP servers should be configured to easily scale by creating a hierarchy of lower level (stratum-2 to stratum-15) servers to accommodate the workload. The width and depth of the hierarchy is dependent on the number of NTP clients as well as the amount of redundancy that is required.

If two NTP servers have not been deployed in the management network, this is a finding.'
  desc 'fix', 'Deploy and implement at least two NTP servers in the management network.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-19370r3_chk'
  tag severity: 'low'
  tag gid: 'V-17860'
  tag rid: 'SV-19152r2_rule'
  tag stig_id: 'NET0810'
  tag gtitle: 'Two NTP servers not implemented in mgmt network'
  tag fix_id: 'F-17801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
