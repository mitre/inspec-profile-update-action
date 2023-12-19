control 'SV-235839' do
  title 'Only trusted, signed images must be on Universal Control Plane (UCP) in Docker Enterprise.'
  desc 'The UCP and Docker Trusted Registry (DTR) components of Docker Enterprise can be used in concert to perform an integrity check of organization-defined software at startup. In the context of Docker Enterprise, software would be analogous to Docker images that have been pulled from trusted or untrusted sources. Docker Hub is the most common upstream endpoint for retrieving Docker images. However, only "Docker Certified" images on Docker Hub are considered trusted and come with SLAs and trusted signatures from their respective vendors. All other images from Docker Hub or other external registries must be carefully inspected and triaged prior to use. Docker Content Trust (DCT) provides for content integrity checking mechanisms on Docker images. DCT can be combined with LDAP, DTR and UCP to enforce image signatures from users/accounts in LDAP. Therefore, to meet the requirements of this control, it is imperative that UCP has LDAP integration enabled and that content trust enforcement is enabled and properly configured.

An operational requirement of this control is that of the required use of an established continuous integration and deployment workflow that effectively dictates exactly what software is allowed to run on UCP.

'
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise.

Verify that all images sitting on a UCP cluster are signed.

via CLI:

Linux: As a Docker EE Admin, execute the following commands using a client bundle:

docker trust inspect $(docker images | awk '{print $1 ":" $2}')

Verify that all image tags in the output have valid signatures.

If the images are not signed, this is a finding.)
  desc 'fix', 'This fix only applies to the UCP component of Docker Enterprise.

Pull and run only signed images on a UCP cluster.

via CLI:

Linux: When using a client bundle, set the "DOCKER_CONTENT_TRUST" environment variable to a value of "1" prior the execution of any of the following commands: docker push, docker build, docker create, docker pull and docker run.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39058r627642_chk'
  tag severity: 'medium'
  tag gid: 'V-235839'
  tag rid: 'SV-235839r627644_rule'
  tag stig_id: 'DKER-EE-003610'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-39021r627643_fix'
  tag satisfies: ['SRG-APP-000386', 'SRG-APP-000480', 'SRG-APP-000484', 'SRG-APP-000485', 'SRG-APP-000475']
  tag 'documentable'
  tag legacy: ['SV-104849', 'V-95711']
  tag cci: ['CCI-001774', 'CCI-002710', 'CCI-002715', 'CCI-002723', 'CCI-002724']
  tag nist: ['CM-7 (5) (b)', 'SI-7 (1)', 'SI-7 (5)', 'SI-7 (8)', 'SI-7 (8)']
end
