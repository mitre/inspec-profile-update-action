control 'SV-235820' do
  title 'Docker Enterprise incoming container traffic must be bound to a specific host interface.'
  desc "By default, Docker containers can make connections to the outside world, but the outside world cannot connect to containers. Each outgoing connection will appear to originate from one of the host machine's own IP addresses. Only allow container services to be contacted through a specific external interface on the host machine.

If there are multiple network interfaces on the host machine, the container can accept connections on the exposed ports on any network interface. This might not be desired and may not be secured. Many times, a particular interface is exposed externally and services such as intrusion detection, intrusion prevention, firewall, load balancing, etc. are run on those interfaces to screen incoming public traffic. Hence, do not accept incoming connections on any interface. Only allow incoming connections from a particular external interface.

By default, Docker exposes the container ports on 0.0.0.0, the wildcard IP address that will match any possible incoming network interface on the host machine."
  desc 'check', "Ensure incoming container traffic is bound to a specific host interface.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle to list all the running instances of containers and their port mapping:

docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'

Review the list and ensure that the exposed container ports are tied to a particular interface and not to the wildcard IP address - 0.0.0.0. If they are, then this is a finding.

For example, if the above command returns as below the container can accept connections on any host interface on the specified port 49153, this is a finding.

Ports=map[443/TCP:<nil> 80/TCP:[map[HostPort:49153 HostIp:0.0.0.0]]]

However, if the exposed port is tied to a particular interface on the host as below, then this recommendation is configured as desired and is compliant.

Ports=map[443/TCP:<nil> 80/TCP:[map[HostIp:10.2.3.4 HostPort:49153]]]"
  desc 'fix', 'Bind the container port to a specific host interface on the desired host port.

Example:
docker run --detach --publish 10.2.3.4:49153:80 nginx

In the example above, the container port 80 is bound to the host port on 49153 and would accept incoming connection only from 10.2.3.4 external interface.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39039r627585_chk'
  tag severity: 'medium'
  tag gid: 'V-235820'
  tag rid: 'SV-235820r627587_rule'
  tag stig_id: 'DKER-EE-002160'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-39002r627586_fix'
  tag 'documentable'
  tag legacy: ['SV-104813', 'V-95675']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
