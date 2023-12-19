control 'SV-235843' do
  title 'The on-failure container restart policy must be is set to 5 in Docker Enterprise.'
  desc 'Using the --restart flag in docker run command, specify a restart policy for how a container should or should not be restarted on exit. Choose the on-failure restart policy and limit the restart attempts to 5.

If indefinitely trying to start the container, it could possibly lead to a denial of service on the host. It could be an easy way to do a distributed denial of service attack especially if there are many containers on the same host. Additionally, ignoring the exit status of the container and always attempting to restart the container leads to non-investigation of the root cause behind containers getting terminated. If a container gets terminated, investigate on the reason behind it instead of just attempting to restart it indefinitely. Thus, it is recommended to use on-failure restart policy and limit it to maximum of 5 restart attempts.

The container would attempt to restart only for 5 times.

By default, containers are not configured with restart policies. Hence, containers do not attempt to restart of their own.'
  desc 'check', %q(Ensure 'on-failure' container restart policy is set to 5.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: RestartPolicyName={{ .HostConfig.RestartPolicy.Name }} MaximumRetryCount={{ .HostConfig.RestartPolicy.MaximumRetryCount }}'
If RestartPolicyName= "" and MaximumRetryCount=0, this is not a finding.

If RestartPolicyName=always, this is a finding.

If RestartPolicyName=on-failure, verify that the number of restart attempts is set to 5 or less by looking at MaximumRetryCount. 

If RestartPolicyName=failure and MaximumRetryCount is > 5, this is a finding.)
  desc 'fix', 'If a container is desired to be restarted on its own, then, for example, start the container as below:

docker run --detach --restart=on-failure:5 nginx'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39062r627654_chk'
  tag severity: 'medium'
  tag gid: 'V-235843'
  tag rid: 'SV-235843r627656_rule'
  tag stig_id: 'DKER-EE-004030'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-39025r627655_fix'
  tag 'documentable'
  tag legacy: ['SV-104859', 'V-95721']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
