control 'SV-204767' do
  title 'The application server must be configured to perform complete application deployments.'
  desc 'Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

When an application is deployed to the application server, if the deployment process does not complete properly and without errors, there is the potential that some application files may not be deployed or may be corrupted and an application error may occur during runtime.

The application server must be able to perform complete application deployments. A partial deployment can leave the server in an inconsistent state. Application servers may provide a transaction rollback function to address this issue.'
  desc 'check', 'Review the application server configuration and documentation to ensure the system is configured to perform complete application deployments.

If the application server is not configured to ensure complete application deployments or provides no rollback functionality, this is a finding.'
  desc 'fix', 'Configure the application server to detect errors that occur during application deployment and to prevent deployment if errors are encountered.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4887r282948_chk'
  tag severity: 'medium'
  tag gid: 'V-204767'
  tag rid: 'SV-204767r508029_rule'
  tag stig_id: 'SRG-APP-000225-AS-000153'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-4887r282949_fix'
  tag 'documentable'
  tag legacy: ['V-35423', 'SV-46710']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
