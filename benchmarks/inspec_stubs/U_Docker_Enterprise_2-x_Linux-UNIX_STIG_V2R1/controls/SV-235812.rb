control 'SV-235812' do
  title 'The Docker Enterprise default seccomp profile must not be disabled.'
  desc 'Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The default Docker seccomp profile works on whitelist basis and allows 311 system calls blocking all others. It should not be disabled unless it hinders the container application usage.

A large number of system calls are exposed to every userland process with many of them going unused for the entire lifetime of the process. Most of the applications do not need all the system calls and thus benefit by having a reduced set of available system calls. The reduced set of system calls reduces the total kernel surface exposed to the application and thus improvises application security.

The default seccomp profile blocks syscalls, regardless of --cap-add passed to the container. Create a custom seccomp profile in such cases. Disable the default seccomp profile by passing --security-opt=seccomp:unconfined on docker run.

When running a container, it uses the default profile unless it is overridden with the --security-opt option.'
  desc 'check', %q(This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Ensure the default seccomp profile is not disabled.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}'

If seccomp:=unconfined, then the container is running without any seccomp profiles and this is a finding.)
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

By default, seccomp profiles are enabled. It is not necessary to do anything unless the user wants to modify the seccomp profile. Do not pass unconfined flags to run a container without the default seccomp profile. Refer to seccomp documentation for details.
https://docs.docker.com/engine/security/seccomp/'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39031r627561_chk'
  tag severity: 'high'
  tag gid: 'V-235812'
  tag rid: 'SV-235812r627563_rule'
  tag stig_id: 'DKER-EE-002070'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38994r627562_fix'
  tag 'documentable'
  tag legacy: ['SV-104797', 'V-95659']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
