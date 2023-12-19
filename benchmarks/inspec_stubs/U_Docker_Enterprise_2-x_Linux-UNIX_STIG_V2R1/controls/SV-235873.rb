control 'SV-235873' do
  title 'Docker Enterprise Swarm services must be bound to a specific host interface.'
  desc 'By default, the docker swarm services will listen to all interfaces on the host, which may not be necessary for the operation of the swarm where the host has multiple network interfaces.

When a swarm is initialized the default value for the --listen-addr flag is 0.0.0.0:2377 which means that the swarm services will listen on all interfaces on the host. If a host has multiple network interfaces this may be undesirable as it may expose the docker swarm services to networks which are not involved in the operation of the swarm.

By passing a specific IP address to the --listen-addr, a specific network interface can be specified limiting this exposure.'
  desc 'check', 'Ensure swarm services are bound to a specific host interface.

Linux: List the network listener on port 2377/TCP (the default for docker swarm) and confirm that it is only listening on specific interfaces. For example, using ubuntu this could be done with the following command:

netstat -lt | grep -i 2377

If the swarm service is not bound to a specific host interface address, this is a finding.'
  desc 'fix', 'Rebuild the cluster and utilize the --listen-addr parameter.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39092r627744_chk'
  tag severity: 'medium'
  tag gid: 'V-235873'
  tag rid: 'SV-235873r627746_rule'
  tag stig_id: 'DKER-EE-006270'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-39055r627745_fix'
  tag 'documentable'
  tag legacy: ['SV-104921', 'V-95783']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
