control 'SV-239847' do
  title 'The vRealize Automation server must be configured to perform complete application deployments.'
  desc 'Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

When an application is deployed to the application server, if the deployment process does not complete properly and without errors, there is the potential that some application files may not be deployed or may be corrupted and an application error may occur during runtime.

The application server must be able to perform complete application deployments. A partial deployment can leave the server in an inconsistent state. Application servers may provide a transaction rollback function to address this issue.'
  desc 'check', 'Obtain the site configuration control policy from the ISSO.

Review site procedures to determine if a site policy exists to verify vRA installation after release into a production environment. The site policy should ensure that the installation was a complete application deployment before users are allowed to conduct business.

If a site policy does not exist or is not being followed, this is a finding.'
  desc 'fix', 'Develop a site policy to ensure deployments are completed before allowing users to use the production environment.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Application'
  tag check_id: 'C-43080r664455_chk'
  tag severity: 'medium'
  tag gid: 'V-239847'
  tag rid: 'SV-239847r879640_rule'
  tag stig_id: 'VRAU-AP-000315'
  tag gtitle: 'SRG-APP-000225-AS-000153'
  tag fix_id: 'F-43039r664456_fix'
  tag 'documentable'
  tag legacy: ['SV-99779', 'V-89129']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
