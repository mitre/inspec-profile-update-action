control 'SV-235827' do
  title 'Docker Enterprise container health must be checked at runtime.'
  desc 'If the container image does not have an HEALTHCHECK instruction defined, use --health-cmd parameter at container runtime for checking container health.

One of the important security triads is availability. If the container image being used does not have a pre-defined HEALTHCHECK instruction, use the --health-cmd parameter to check container health at runtime. Based on the reported health status, take necessary actions.

By default, health checks are not done at container runtime.'
  desc 'check', %q(Ensure container health is checked at runtime.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

Run the below command and ensure that all the containers are reporting health status:

docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Health={{ .State.Health.Status }}'

If Health does not = "Healthy", this is a finding.)
  desc 'fix', "Run the container using --health-cmd and the other parameters, or include the HEALTHCHECK instruction in the Dockerfiles.

Example:
docker run -d --health-cmd='stat /etc/passwd || exit 1' nginx"
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39046r627606_chk'
  tag severity: 'medium'
  tag gid: 'V-235827'
  tag rid: 'SV-235827r627608_rule'
  tag stig_id: 'DKER-EE-002770'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-39009r627607_fix'
  tag 'documentable'
  tag legacy: ['SV-104825', 'V-95687']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
