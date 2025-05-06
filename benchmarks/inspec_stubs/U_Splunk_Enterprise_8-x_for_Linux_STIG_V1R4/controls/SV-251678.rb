control 'SV-251678' do
  title 'When Splunk Enterprise is distributed over multiple servers, each server must be configured to disable non-essential capabilities.'
  desc 'Applications are capable of providing a wide variety of functions and services. Some of the functions and services may not be necessary to support the configuration. This becomes more of an issue in distributed environments, where the application functions are spread out over multiple servers. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.'
  desc 'check', 'If the Splunk Installation is not distributed among multiple servers, this check is N/A.

Select Settings >> Monitoring Console.

In the Monitoring Console, select Settings >> General Setup.

Check the Mode type.

If set to Standalone, then this requirement is N/A, as all functions provided are necessary for operation.

If Mode is set to Distributed, check that each instance is configured only with the server roles necessary for the implementation.

If unused roles are configured, this is a finding.'
  desc 'fix', 'If the Splunk Installation is not distributed among multiple servers, this fix is N/A.

Select Settings >> Monitoring Console.

In the Monitoring Console, select Settings >> General Setup.

Set the Mode type based on the implementation design.

If Mode is set to Distributed, set each instance only with the server roles necessary for the desired functions.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55116r808268_chk'
  tag severity: 'medium'
  tag gid: 'V-251678'
  tag rid: 'SV-251678r879587_rule'
  tag stig_id: 'SPLK-CL-000300'
  tag gtitle: 'SRG-APP-000141-AU-000090'
  tag fix_id: 'F-55070r808269_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
