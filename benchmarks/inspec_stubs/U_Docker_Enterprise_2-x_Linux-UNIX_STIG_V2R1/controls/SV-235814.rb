control 'SV-235814' do
  title 'Docker Enterprise exec commands must not be used with the user option.'
  desc 'Do not docker exec with --user option.

Using --user option in docker exec executes the command within the container as that user. Do not run docker exec with the --user option , especially when running containers with dropped capabilities or with enhanced restrictions. For example, suppose the container is running as tomcat user (or any other non-root user), it would be possible to run a command through docker exec as rootwith --user=root option. 

By default, docker exec command runs without --user option.'
  desc 'check', 'This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Ensure docker exec commands are not used with the user option.

via CLI:

Linux: As a trusted user on the host operating system, use the below command to filter out docker exec commands that used --privileged option.

sudo ausearch -k docker | grep exec | grep user

If there are any in the output, then this is a finding.'
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Do not use --user option in docker exec command.

A reference for the docker exec command can be found at https://docs.docker.com/engine/reference/commandline/exec/.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39033r627567_chk'
  tag severity: 'medium'
  tag gid: 'V-235814'
  tag rid: 'SV-235814r627569_rule'
  tag stig_id: 'DKER-EE-002090'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38996r627568_fix'
  tag 'documentable'
  tag legacy: ['SV-104801', 'V-95663']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
