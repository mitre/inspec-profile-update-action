control 'SV-235837' do
  title 'Docker Enterprise network ports on all running containers must be limited to what is needed.'
  desc 'By itself, Docker Engine - Enterprise is configured by default to listen for API requests via a UNIX domain socket (or IPC socket) created at /var/run/docker.sock on supported Linux distributions and via a named pipe at npipe:////./pipe/docker_engine on Windows Server 2016 and newer. In this configuration, this control is not applicable. Docker Engine - Enterprise can also be configured to listen for API requests via additional socket types, including both TCP and FD (only on supported systemd-based Linux distributions). If configured to listen for API requests via the TCP socket type over TCP port 2376 and with the daemon flags and SSL certificates, then, at a minimum, TLS 1.2 is used for encryption; therefore this control is applicable and is inherently met in this configuration. If configured to listen for API requests via the TCP socket type, but without TLS verification and certifications, then the instance remains vulnerable and is not properly configured to meet the requirements of this control. If configured to listen for API requests via the fd socket type, then this control is not applicable. More information can be found at https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option. The TCP socket binding should be disabled when running Engine as part of a UCP cluster.

A container can be run just with the ports defined in the Dockerfile for its image or can be arbitrarily passed run time parameters to open a list of ports. Additionally, over time, Dockerfiles may undergo various changes and the list of exposed ports may or may not be relevant to the application running within the container. Opening unneeded ports increase the attack surface of the container and the containerized application. Per the requirements set forth by the System Security Plan (SSP), ensure only needed ports are open on all running containers.'
  desc 'check', "Verify that only needed ports are open on all running containers.

via CLI: As a Docker EE admin, execute the following command using a client bundle:

docker ps -q | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'

Review the list and ensure that the ports mapped are the ones really needed for the containers per the requirements set forth by the SSP.

If ports are not documented and approved in the SSP, this is a finding."
  desc 'fix', 'Publish only needed ports for all container images and running containers per the requirements set forth by the SSP.

Update Dockerfiles and set or remove any EXPOSE lines accordingly.

To ignore exposed ports as defined by a Dockerfile during container start, do not pass the "-P/--publish-all" flag to the Docker commands.

When publishing needed ports at container start, use the "-p/--publish" flag to explicitly define the ports that are needed.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39056r627636_chk'
  tag severity: 'medium'
  tag gid: 'V-235837'
  tag rid: 'SV-235837r627638_rule'
  tag stig_id: 'DKER-EE-003560'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-39019r627637_fix'
  tag 'documentable'
  tag legacy: ['SV-104845', 'V-95707']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
