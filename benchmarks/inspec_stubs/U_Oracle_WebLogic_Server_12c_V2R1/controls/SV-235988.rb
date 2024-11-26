control 'SV-235988' do
  title 'Oracle WebLogic must protect the integrity of applications during the processes of data aggregation, packaging, and transformation in preparation for deployment.'
  desc 'Information can be subjected to unauthorized changes (e.g., malicious and/or unintentional modification) at information aggregation or protocol transformation points. It is therefore imperative the application take steps to validate and assure the integrity of data while at these stages of processing. 

The application server must ensure the integrity of data that is pending transfer for deployment is maintained. If the application were to simply transmit aggregated, packaged, or transformed data without ensuring the data was not manipulated during these processes, then the integrity of the data and the application itself may be called into question.'
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
  tag check_id: 'C-39207r628740_chk'
  tag severity: 'low'
  tag gid: 'V-235988'
  tag rid: 'SV-235988r628742_rule'
  tag stig_id: 'WBLC-08-000235'
  tag gtitle: 'SRG-APP-000435-AS-000069'
  tag fix_id: 'F-39170r628741_fix'
  tag 'documentable'
  tag legacy: ['SV-70587', 'V-56333']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
