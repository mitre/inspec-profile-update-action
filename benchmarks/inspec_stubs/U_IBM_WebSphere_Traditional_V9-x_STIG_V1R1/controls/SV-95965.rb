control 'SV-95965' do
  title 'The WebSphere Application Server high availability applications must be configured to fail over to another system in the event of log subsystem failure.'
  desc 'This requirement is dependent upon system MAC and availability. If the system MAC and availability do not specify redundancy requirements, this requirement is NA.

It is critical that, when a system is at risk of failing to process logs as required, it detects and takes action to mitigate the failure.

Application servers must be capable of failing over to another system which can handle application and logging functions upon detection of an application log processing failure. This will allow continual operation of the application and logging functions while minimizing the loss of operation for the users and loss of log data.'
  desc 'check', 'If the System Security Plan documentation does not require redundancy, this requirement is NA.

Click Servers >> Clusters >> WebSphere application server clusters.

Ensure you have a cluster defined for every application requiring redundancy.

If there is not a cluster defined for every application requiring redundancy, this is a finding.'
  desc 'fix', 'In the admin console, Click Servers >> Clusters >> WebSphere application server clusters.

Define a cluster for every high availability application as outlined in the System Security Plan documentation.

Refer to vendor documentation for steps on creating a fail over cluster.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80947r1_chk'
  tag severity: 'low'
  tag gid: 'V-81251'
  tag rid: 'SV-95965r1_rule'
  tag stig_id: 'WBSP-AS-000670'
  tag gtitle: 'SRG-APP-000109-AS-000070'
  tag fix_id: 'F-88031r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
