control 'SV-235972' do
  title 'Oracle WebLogic must utilize encryption when using LDAP for authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. 

Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Monitoring' -> 'Port Usage' 
3. In the results table, ensure the 'Protocol' column does not contain the value 'LDAP' (only 'LDAPS')

If LDAP is being used and the 'Protocol' column contains the value 'LDAP', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which is assigned 'LDAP' protocol
4. Utilize 'Change Center' to create a new change session 
5. From 'Configuration' tab -> 'General' tab, deselect the 'Listen Port Enabled' checkbox
6. Select the 'SSL Listen Port Enabled checkbox
7. Enter a valid port value in the 'SSL Listen Port' field and click 'Save'
8. Review the 'Port Usage' table in EM again to ensure the 'Protocol' column does not contain the value 'LDAP'"
  impact 0.7
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39191r628692_chk'
  tag severity: 'high'
  tag gid: 'V-235972'
  tag rid: 'SV-235972r628694_rule'
  tag stig_id: 'WBLC-05-000169'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag fix_id: 'F-39154r628693_fix'
  tag 'documentable'
  tag legacy: ['SV-70547', 'V-56293']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
