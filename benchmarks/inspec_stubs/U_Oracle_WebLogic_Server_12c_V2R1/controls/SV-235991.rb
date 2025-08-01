control 'SV-235991' do
  title 'Oracle WebLogic must fail securely in the event of an operational failure.'
  desc 'Fail secure is a condition achieved by the application server in order to ensure that in the event of an operational failure, the system does not enter into an unsecure state where intended security properties no longer hold.

An example of secure failure is when an application server is configured for secure LDAP (LDAPS) authentication. If the application server fails to make a successful LDAPS connection it does not try to use unencrypted LDAP instead.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure values in the 'Protocol' column each end with 's' (secure)

If the protocols are not secure, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which is assigned a protocol which does not end in 's' (secure)
4. Utilize 'Change Center' to create a new change session 
5. From 'Configuration' tab -> 'General' tab, deselect the 'Listen Port Enabled' checkbox
6. Select the 'SSL Listen Port Enabled checkbox
7. Enter a valid port value in the 'SSL Listen Port' field and click 'Save'
8. Review the 'Port Usage' table in EM again to ensure all values in the 'Protocol' column end with 's' (secure)"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39210r628749_chk'
  tag severity: 'medium'
  tag gid: 'V-235991'
  tag rid: 'SV-235991r628751_rule'
  tag stig_id: 'WBLC-08-000238'
  tag gtitle: 'SRG-APP-000225-AS-000166'
  tag fix_id: 'F-39173r628750_fix'
  tag 'documentable'
  tag legacy: ['SV-70597', 'V-56343']
  tag cci: ['CCI-001126']
  tag nist: ['SC-7 (18)']
end
