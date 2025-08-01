control 'SV-235788' do
  title 'Docker Incs official GPG key must be added to the host using the users operating systems respective package repository management tooling.'
  desc 'All packaged components of Docker Enterprise are digitally signed using GPG keys maintained by Docker, Inc. The Docker Engine - Enterprise daemon, itself, is digitally signed. Furthermore, all Docker, Inc-managed Linux repositories are themselves signed using GPG keys. On Windows, if Docker is installed via the PowerShell PackageManagement (aka OneGet) provider, the provider is managed by Microsoft, and provider artifacts are signed by Microsoft. The Universal Control Plane (UCP) and Docker Trusted Registry (DTR) installation images are digitally signed by Docker, Inc using Docker Content Trust.'
  desc 'check', %q(For Linux systems, verify that the host is configured to trust Docker Inc's repository GPG keys and that Docker Engine - Enterprise is installed from these repositories as such. If installing in an offline environment, validate that the Engine's package signature matches that as published by Docker, Inc.

Execute the following command to validate the Docker image signature digests of UCP and DTR:

docker trust inspect docker/ucp:[ucp_version] docker/dtr:[dtr_version]

Check that the "SignedTags" array for both images in the output includes a "Digest" field. If the SignedTags array does not contain a Digest field, this is a finding.)
  desc 'fix', "For Linux systems, add Docker Inc's official GPG key to the host using the operating system's respective package repository management tooling. If not using a package repository to install/update Docker Engine - Enterprise, verify that the Engine's package signature matches that as published by Docker, Inc.

When retrieving the UCP and DTR installation images, use Docker, Inc's officially managed image repositories as follows:

docker.io/docker/ucp:[ucp_version]
docker.io/docker/dtr:[dtr_version]

If downloading the UCP and DTR images for offline installation, use only Docker, Inc's officially managed package links as follows:

https://docs.docker.com/ee/ucp/admin/install/install-offline/
https://docs.docker.com/ee/dtr/admin/install/install-offline/"
  impact 0.3
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39007r627489_chk'
  tag severity: 'low'
  tag gid: 'V-235788'
  tag rid: 'SV-235788r627491_rule'
  tag stig_id: 'DKER-EE-001770'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-38970r627490_fix'
  tag 'documentable'
  tag legacy: ['SV-104747', 'V-95609']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
