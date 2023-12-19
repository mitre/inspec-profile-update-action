control 'SV-235790' do
  title 'On Linux, a non-AUFS storage driver in the Docker Engine - Enterprise component of Docker Enterprise must be used.'
  desc 'The aufs storage driver is the oldest storage driver. It is based on a Linux kernel patch-set that is unlikely to be merged into the main Linux kernel. aufs driver is also known to cause some serious kernel crashes. aufs just has legacy support from Docker. Most importantly, aufs is not a supported driver in many Linux distributions using latest Linux kernels.

Docker Enterprise includes the following capabilities that are considered non-essential:

*NOTE: disabling these capabilities negatively affects the operation of Universal Control Plane (UCP) and Docker Trusted Registry (DTR) and should be disregarded when UCP and DTR are installed. The security capabilities provided by UCP and DTR offset any potential vulnerabilities associated with not disabling these essential capabilities the Engine provides.

(Docker Engine - Enterprise: Standalone) - The majority of these items were originally identified as part of the CIS Docker Benchmark, which as of the CIS Docker Benchmark v1.2.0, are still applicable to Docker Engine - Enterprise 18.09
- inter-container communication (icc)* (CIS Docker Benchmark Recommendation 2.1)
- insecure registry communication (CIS Docker Benchmark Recommendation 2.4)
- AUFS storage driver (applicable on Linux only) (CIS Docker Benchmark Recommendation 2.5)
- listening on the TCP Daemon socket
- userland proxy for loopback traffic* (CIS Docker Benchmark Recommendation 2.15)
- experimental features (CIS Docker Benchmark Recommendation 2.17)
- Swarm Mode (CIS Docker Benchmark Recommendation 7.1)

(Docker Engine - Enterprise: As part of a UCP cluster)
- insecure registry communication (CIS Docker Benchmark Recommendation 2.4)
- AUFS storage driver (applicable on Linux only) (CIS Docker Benchmark Recommendation 2.5)
- listening on the TCP Daemon socket
- experimental features (CIS Docker Benchmark Recommendation 2.17)

(UCP)
- Managed user database
- self-signed certificates
- periodic usage reporting and API tracking
- allow users and administrators to schedule containers on all nodes, including UCP managers and DTR nodes

(DTR)
- periodic data usage/analytics reporting
- create repository on push
- self-signed certificates'
  desc 'check', 'This check only applies to the Docker Engine - Enterprise component of Docker Enterprise and only when it is used on a Linux host operating system.

via CLI:

Linux: As a trusted user on the underlying host operating system, execute the following command:

docker info | grep -e "^Storage Driver:\\s*aufs\\s*$"

If the Storage Driver setting contains *aufs, then this is a finding. If the above command returns no values, this is not a finding.'
  desc 'fix', 'This fix only applies to the Docker Engine - Enterprise component of Docker Enterprise and only when it is used on a Linux host operating system.

via CLI:

Linux: As a trusted user on the underlying host operating system, edit the "/etc/docker/daemon.json" file and set the "storage-driver" property to a value that is not "aufs". If the daemon.json file does not exist, it must be created.

Restart the Docker daemon.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39009r627495_chk'
  tag severity: 'medium'
  tag gid: 'V-235790'
  tag rid: 'SV-235790r627497_rule'
  tag stig_id: 'DKER-EE-001810'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38972r627496_fix'
  tag 'documentable'
  tag legacy: ['SV-104751', 'V-95613']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
