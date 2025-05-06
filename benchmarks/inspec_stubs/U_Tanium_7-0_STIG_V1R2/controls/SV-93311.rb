control 'SV-93311' do
  title 'Tanium Computer Groups must be used to restrict console users from affecting changes to unauthorized computers.'
  desc 'Computer Groups allow a site running Tanium to assign responsibility of specific Computer Groups to specific Tanium console users. By doing so, a desktop administrator, for example, will not have the ability to enforce an action against a high visibility server.

For large sites, it is crucial to have the Computer Groups and while a smaller site might not seem to require Computer Groups, creating them provides for a cleaner implementation. All sites will be required to have some kind of Computer Groups configured other than the default "All Computers".'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Computer Groups" tab.

Under the "Name" column, verify specific groups exist other than the default "All Computers" and "No Computers".

If site or organization specific computer groups do not exist, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console and then click on "Administration".

Select the "Computer Groups" tab.

Configure specific Computer Groups in order to facilitate the management of computers by authorized individuals for those computers.

Note: Tanium offer two ways to define computer groups. Refer to documentation for explanation found here: https://docs.tanium.com/platform_user/platform_user/console_computer_groups.html#Computer_Group_types

Note: Active Directory Computer Groups may also be used to sync with Tanium Computer Groups as a means to satisfy this requirement.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78175r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78605'
  tag rid: 'SV-93311r1_rule'
  tag stig_id: 'TANS-CN-000004'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-85341r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
