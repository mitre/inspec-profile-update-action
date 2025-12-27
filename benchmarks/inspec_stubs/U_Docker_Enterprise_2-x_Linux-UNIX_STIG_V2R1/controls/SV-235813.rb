control 'SV-235813' do
  title 'Docker Enterprise exec commands must not be used with privileged option.'
  desc 'Do not use docker exec with --privileged option.

Using --privileged option in docker exec gives extended Linux capabilities to the command. Do not run docker exec with the --privileged option, especially when running containers with dropped capabilities or with enhanced restrictions. By default, docker exec command runs without --privileged option.'
  desc 'check', 'This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Ensure the default seccomp profile is not disabled, if applicable.

via CLI:

Linux: As a trusted user on the host operating system, use the below command to filter out docker exec commands that used --privileged option.

sudo ausearch -k docker | grep exec | grep privileged

If there are any in the output, then this is a finding.'
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Do not use --privileged option in docker exec command.

A reference for the docker exec command can be found at https://docs.docker.com/engine/reference/commandline/exec/.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39032r627564_chk'
  tag severity: 'high'
  tag gid: 'V-235813'
  tag rid: 'SV-235813r627566_rule'
  tag stig_id: 'DKER-EE-002080'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38995r627565_fix'
  tag 'documentable'
  tag legacy: ['SV-104799', 'V-95661']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
