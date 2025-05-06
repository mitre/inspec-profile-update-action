control 'SV-254882' do
  title 'Tanium Computer Groups must be used to restrict console users from affecting changes to unauthorized computers.'
  desc 'Computer Groups allow a site running Tanium to assign responsibility of specific Computer Groups to specific Tanium console users. By doing so, a desktop administrator, for example, will not have the ability to enforce an action against a high visibility server.
 
For large sites, it is crucial to have the Computer Groups. While a smaller site might not seem to require Computer Groups, creating them provides for a cleaner implementation. All sites will be required to have some kind of Computer Groups configured other than the default "All Computers".'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.
  
2. Click "Administration" on the top navigation banner.
  
3. Select the "Computer Groups" tab.
  
4. Under the "Name" column, verify organization-specific computer groups match the organization-defined list in the system security plan (SSP). 
  
If site- or organization-specific computer groups do not match or exist, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with multi-factor authentication.
  
2. Click "Administration" on the top navigation banner.
  
3. Select the "Computer Groups" tab.
  
4. Configure specific Computer Groups to facilitate the management of computers by authorized individuals for those computers.
  
Note: Tanium offers two ways to define computer groups. Refer to documentation for explanation found here: https://docs.tanium.com/platform_user/platform_user/console_computer_groups.html#Computer_Group_types.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58495r867544_chk'
  tag severity: 'medium'
  tag gid: 'V-254882'
  tag rid: 'SV-254882r867546_rule'
  tag stig_id: 'TANS-AP-000100'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-58439r867545_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
