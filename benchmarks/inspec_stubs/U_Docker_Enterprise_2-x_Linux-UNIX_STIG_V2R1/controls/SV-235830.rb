control 'SV-235830' do
  title 'Docker Enterprise images must be built with the USER instruction to prevent containers from running as root.'
  desc 'Both the Universal Control Plane (UCP) and Docker Trusted Registry (DTR) components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. The eNZi backplane includes its own managed user database, and also allows for LDAP integration in UCP and DTR. To meet the requirements of this control, configure LDAP integration. Apply an applicable set of role-based access control (RBAC) policies using the built-in capabilities provided by UCP in order to prevent organization-defined software from executing at higher privilege levels than users executing the software.

By default, Docker images that are built without the USER instruction will be run as containers as root. Therefore, it is imperative that container images include the USER instruction and that the referenced UID/GID has been defined in the base image or previous instruction set.'
  desc 'check', "Verify that all containers are running as non-root users.

via CLI: As a Docker EE admin, execute the following command using a client bundle:

docker ps -q -a | xargs docker inspect --format '{{ .Id }}: User={{ .Config.User }}'

Ensure that a non-admin username or user ID is returned for all containers in the output.

If User is 0, root or undefined, this is a finding."
  desc 'fix', 'Set a non-root user for all container images.

Include the following line in all Dockerfiles where username or ID refers to the user that can be found in the container base image or one that is created as part of that same Dockerfile:

USER [username/ID]'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39049r627615_chk'
  tag severity: 'medium'
  tag gid: 'V-235830'
  tag rid: 'SV-235830r627617_rule'
  tag stig_id: 'DKER-EE-003200'
  tag gtitle: 'SRG-APP-000342'
  tag fix_id: 'F-39012r627616_fix'
  tag 'documentable'
  tag legacy: ['SV-104831', 'V-95693']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
