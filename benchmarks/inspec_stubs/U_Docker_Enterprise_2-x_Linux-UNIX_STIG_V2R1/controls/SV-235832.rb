control 'SV-235832' do
  title 'The Docker Enterprise max-size and max-file json-file drivers logging options in the daemon.json configuration file must be configured to allocate audit record storage capacity for Universal Control Plane (UCP) and Docker Trusted Registry (DTR) per the requirements set forth by the System Security Plan (SSP).'
  desc %q(By default, the UCP and DTR components of Docker Enterprise leverage the "json-file" Engine logging driver. This driver has configurable "max-size" and "max-file" options which are applicable in the context of this control. The "max-size" option defines the maximum size of the log before it is rolled. By default it is set to "unlimited" and is never rolled. The "max-file" option defines the maximum number of log files that can be present whereby if rolling the logs creates excess files, the oldest file is removed. This setting is only effective when "max-size" is also set. By default, "max-file" is set to "1".

The Docker Engine - Enterprise audit logs are stored in default locations according to the chart on this site https://docs.docker.com/config/daemon/#read-the-logs. For the Engine's daemon logs, allocate sufficient storage for the default log locations on the underlying host operating system per the requirements set forth by the SSP.)
  desc 'check', 'This check only applies to the Docker Engine - Enterprise component of Docker Enterprise.

via CLI:

Linux: Execute the following commands as a trusted user on the host operating system:

cat /etc/docker/daemon.json

Verify that the "log-opts" object includes the "max-size" and "max-file" properties and that they are set according to requirements specified in the SSP. If they are not configured according to values defined in the SSP, this is a finding.'
  desc 'fix', %q(This fix only applies to the Docker Engine - Enterprise component of Docker Enterprise.

via CLI:

Linux: Execute the following commands as a trusted user on the host operating system:

Open "/etc/docker/daemon.json" for editing. If the file doesn't exist, it must be created.

Set the "log-opts" object and its "max-size" and "max-file" properties according to values defined in the SSP.

Save the file. Restart the Docker daemon.)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39051r627621_chk'
  tag severity: 'medium'
  tag gid: 'V-235832'
  tag rid: 'SV-235832r695335_rule'
  tag stig_id: 'DKER-EE-003310'
  tag gtitle: 'SRG-APP-000357'
  tag fix_id: 'F-39014r627622_fix'
  tag 'documentable'
  tag legacy: ['SV-104835', 'V-95697']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
