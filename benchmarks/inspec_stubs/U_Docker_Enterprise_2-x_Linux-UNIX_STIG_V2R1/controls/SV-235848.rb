control 'SV-235848' do
  title 'Docker Swarm must have the minimum number of manager nodes.'
  desc 'Ensure that the minimum number of required manager nodes is created in a swarm.

Manager nodes within a swarm have control over the swarm and change its configuration modifying security parameters. Having excessive manager nodes could render the swarm more susceptible to compromise. If fault tolerance is not required in the manager nodes, a single node should be elected as a manger. If fault tolerance is required then the smallest practical odd number to achieve the appropriate level of tolerance should be configured.'
  desc 'check', "Ensure the correct range of manager nodes have been created in a swarm.

via CLI:

Linux: As a Docker EE Admin, follow the steps below using a Universal Control Plane (UCP) client bundle:

Run the following command.
docker info --format '{{ .Swarm.Managers }}' 

Alternatively run the below command.

docker node ls | grep 'Leader'

Ensure the number of leaders is between 1 and 3. If the number of leaders is not 1, 2 or 3, this is a finding."
  desc 'fix', 'If an excessive number of managers is configured, the excess can be demoted to worker using the following command:

docker node demote <ID> 
Where is the node ID value of the manager to be demoted.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39067r627669_chk'
  tag severity: 'medium'
  tag gid: 'V-235848'
  tag rid: 'SV-235848r627671_rule'
  tag stig_id: 'DKER-EE-005060'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39030r627670_fix'
  tag 'documentable'
  tag legacy: ['SV-104869', 'V-95731']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
