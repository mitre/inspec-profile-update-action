control 'SV-253691' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'List all plugins and determine which are acceptable. 

MariaDB> SHOW PLUGINS;

If unused plugins are installed and are not documented and authorized, this is a finding.'
  desc 'fix', 'To uninstall the plugin but leave the libraries in place: 

MariaDB> UNINSTALL PLUGIN plugin_name;

To uninstall the plugin and the associated libraries: 

MariaDB> UNINSTALL SONAME plugin_name;'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57143r841596_chk'
  tag severity: 'medium'
  tag gid: 'V-253691'
  tag rid: 'SV-253691r841598_rule'
  tag stig_id: 'MADB-10-003200'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-57094r841597_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
