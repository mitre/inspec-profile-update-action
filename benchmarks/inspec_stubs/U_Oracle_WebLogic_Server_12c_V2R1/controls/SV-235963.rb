control 'SV-235963' do
  title 'Oracle WebLogic must utilize automated mechanisms to prevent program execution on the information system.'
  desc 'The application server must provide a capability to halt or otherwise disable the automatic execution of deployed applications until such time that the application is considered part of the established application server baseline. Deployment to the application server should not provide a means for automatic application start-up should the application server itself encounter a restart condition.'
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
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39182r628665_chk'
  tag severity: 'low'
  tag gid: 'V-235963'
  tag rid: 'SV-235963r628667_rule'
  tag stig_id: 'WBLC-03-000129'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39145r628666_fix'
  tag 'documentable'
  tag legacy: ['SV-70529', 'V-56275']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
