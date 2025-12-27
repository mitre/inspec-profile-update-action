control 'SV-235986' do
  title 'Oracle WebLogic must be configured to perform complete application deployments.'
  desc 'Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

When an application is deployed to the application server, if the deployment process does not complete properly and without errors, there is the potential that some application files may not be deployed or may be corrupted and an application error may occur during runtime.

The application server must be able to perform complete application deployments. A partial deployment can leave the server in an inconsistent state. Application servers may provide a transaction rollback function to address this issue.'
  desc 'check', "1. Access AC 
2. From 'Domain Structure', select the top-level domain 
3. Select 'Configuration' tab -> 'General' tab 
4. Ensure 'Production Mode' checkbox is selected

If the 'Production Mode' checkbox is not selected, this is a finding."
  desc 'fix', "1. Access AC 
2. From 'Domain Structure', select the top-level domain 
3. Select 'Configuration' tab -> 'General' tab 
4. Check 'Production Mode' checkbox. Click 'Save'
5. Restart all servers"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39205r628734_chk'
  tag severity: 'medium'
  tag gid: 'V-235986'
  tag rid: 'SV-235986r628736_rule'
  tag stig_id: 'WBLC-08-000229'
  tag gtitle: 'SRG-APP-000225-AS-000153'
  tag fix_id: 'F-39168r628735_fix'
  tag 'documentable'
  tag legacy: ['SV-70581', 'V-56327']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
