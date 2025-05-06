control 'SV-235845' do
  title 'Docker Enterprise older Universal Control Plane (UCP) and Docker Trusted Registry (DTR) images must be removed from all cluster nodes upon upgrading.'
  desc 'When upgrading either the UCP or DTR components of Docker Enterprise, the newer images are pulled (or unpacked if offline) onto Engine nodes in a cluster. Once the upgrade is complete, one must manually remove all old image version from the cluster nodes to meet the requirements of this control.

When upgrading the Docker Engine - Enterprise component of Docker Enterprise, the old package version is automatically replaced.'
  desc 'check', "Verify that all outdated UCP and DTR container images have been removed from all nodes in the cluster.

via CLI: As a Docker EE admin, execute the following command using a client bundle:

docker images --filter reference='docker/[ucp|dtr]*'

Verify that there are no tags listed that are older than the currently installed versions of UCP and DTR.

If any of the tags listed are older than the currently installed versions of UCP and DTR, then this is a finding."
  desc 'fix', "Remove all outdated UCP and DTR container images from all nodes in the cluster:

via CLI: As a Docker EE admin, execute the following commands using a client bundle:

docker rmi -f $(docker images --filter reference='docker/ucp*:[outdated_tags]' -q)
docker rmi -f $(docker images --filter reference='docker/dtr*:[outdated_tags]' -q)"
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39064r627660_chk'
  tag severity: 'medium'
  tag gid: 'V-235845'
  tag rid: 'SV-235845r627662_rule'
  tag stig_id: 'DKER-EE-004130'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-39027r627661_fix'
  tag 'documentable'
  tag legacy: ['SV-104863', 'V-95725']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
