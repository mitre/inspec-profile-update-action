control 'SV-235872' do
  title 'Docker Enterprise data exchanged between Linux containers on different nodes must be encrypted on the overlay network.'
  desc 'Encrypt data exchanged between containers on different nodes on the overlay network.

By default, data exchanged between containers on different nodes on the overlay network is not encrypted. This could potentially expose traffic between the container nodes.'
  desc 'check', %q(Ensure data exchanged between containers are encrypted on different nodes on the overlay network.

via CLI:

Linux: As a Docker EE Admin, follow the steps below using a Universal Control Plane (UCP) client bundle:

Run the below command and ensure that each overlay network has been encrypted. 

docker network ls --filter driver=overlay --quiet | xargs docker network inspect --format '{{.Name}} {{ .Options }}' | grep -v "dtr\|interlock map\|ingress map"

If the network overlay drivers do not show [com.docker.network.driver.overlay"encrypted:" ask for evidence that encryption is being handled at the application layer, if no evidence of encryption at the network or application layer is provided, this is a finding.)
  desc 'fix', 'Create overlay network with --opt encrypted flag. 

Example:
docker network create --opt encrypted --driver overlay my-network'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39091r627741_chk'
  tag severity: 'medium'
  tag gid: 'V-235872'
  tag rid: 'SV-235872r627743_rule'
  tag stig_id: 'DKER-EE-006240'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-39054r627742_fix'
  tag 'documentable'
  tag legacy: ['SV-104919', 'V-95781']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
