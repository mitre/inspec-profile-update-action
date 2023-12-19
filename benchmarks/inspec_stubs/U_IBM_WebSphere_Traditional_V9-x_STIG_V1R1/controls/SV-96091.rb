control 'SV-96091' do
  title 'The WebSphere Application Server must be configured to perform complete application deployments when using A/B clusters.'
  desc 'Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

When an application is deployed to the application server, if the deployment process does not complete properly and without errors, there is the potential that some application files may not be deployed or may be corrupted and an application error may occur during runtime.

The application server must be able to perform complete application deployments. A partial deployment can leave the server in an inconsistent state. Application servers may provide a transaction rollback function to address this issue.'
  desc 'check', 'Review System Security Plan documentation to determine if the server is configured to use A/B clusters.

If the System Security Plan does not specify utilizing A/B clusters, the requirement is NA.

From the administration console, select WebSphere application server clusters.

Select each cluster name.

Select cluster members.

If the weight of any cluster member is "0", this is a finding.'
  desc 'fix', 'From the administration console, select WebSphere application server clusters.

Select each cluster name.

Select cluster members >> Details.

Set all cluster members configured weight to a non-zero value.'
  impact 0.3
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81087r1_chk'
  tag severity: 'low'
  tag gid: 'V-81377'
  tag rid: 'SV-96091r1_rule'
  tag stig_id: 'WBSP-AS-001470'
  tag gtitle: 'SRG-APP-000225-AS-000153'
  tag fix_id: 'F-88163r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
