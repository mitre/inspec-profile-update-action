control 'SV-254915' do
  title 'The Tanium application must be configured for LDAP user/group synchronization to map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.   

2. Click "Administration" on the top navigation banner.   

3. Under "Configuration," select "LDAP/AD Sync Configurations".   

4. Verify a sync exists under "Enabled Servers".  

If no sync exists, this is a finding. If sync exists under "Disabled Servers" and there are no Enabled Servers, this is a finding."'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.   

2. Click "Administration" on the top navigation banner.   

3. Under "Configuration," select "LDAP/AD Sync Configurations".   

4. Verify a sync exists under "Enabled Servers".  

5. If no sync exists, click "Add Server".  

6. Fill in the correct information for connecting to the organizations LDAP server. Work with a systems administrator to get this information if necessary.  

7. Click "Save".

8. If a sync exists and it is disabled, click the edit icon.

9. Change the status to "enabled".

10. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58528r867643_chk'
  tag severity: 'medium'
  tag gid: 'V-254915'
  tag rid: 'SV-254915r867645_rule'
  tag stig_id: 'TANS-AP-000490'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-58472r867644_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
