control 'SV-253816' do
  title 'The Tanium Application Server must be configured to only use LDAP for account management functions.'
  desc "Enterprise environments make application account management challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. 
 
To reduce risk, the Tanium application must be configured to allow for LDAP to provide account management functions that immediately enforce the organization's current account policy."
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.
 
2. Click "Administration" on the top navigation banner.
 
3. Under "Configuration", select "LDAP/AD Sync Configurations".
 
4. Ensure LDAP sync is enabled.
 
If LDAP is not enabled, this is a finding.'
  desc 'fix', 'Vendor documentation can be downloaded from https://docs.tanium.com/platform_user/platform_user/console_using_ldap.html?Highlight=LDAP.
 
1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration", select "LDAP/AD Sync Configurations". 

4. Follow the vendor documentation titled "Integrating with LDAP Servers" to implement correct configuration settings for this requirement.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57268r842474_chk'
  tag severity: 'medium'
  tag gid: 'V-253816'
  tag rid: 'SV-253816r842476_rule'
  tag stig_id: 'TANS-CN-000003'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-57219r842475_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
