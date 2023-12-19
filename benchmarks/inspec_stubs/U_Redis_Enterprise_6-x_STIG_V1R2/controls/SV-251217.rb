control 'SV-251217' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Modules are not needed for Redis Enterprise to function properly but can make some tasks easier. The following come by default on Redis Enterprise 6:
RedisBloom
RediSearch
RedisGraph
RedisJSON
RedisTimeSeries

More information can be found at: https://docs.redislabs.com/latest/modules/?s=modules'
  desc 'check', 'Redis Enterprise comes with a suite of capabilities sorted into modules. These modules can be removed if deemed unnecessary. Modules are not needed for Redis Enterprise to function properly but can make some tasks easier. Check the installed modules in the UI at the following location:
1. Log in to the Redis Enterprise UI as an Admin user.
2. Navigate to the Settings tab.
3. View the Redis Modules tab.

If unused components or features are installed and are not documented and authorized, this is a finding.'
  desc 'fix', 'Modules are not needed for Redis Enterprise to function properly but can make some tasks easier. To view/remove installed modules from the UI:
1. Click "Settings" in the red banner.
2. Click Redis modules.
3. Find the module to be removed and click the trash can icon on the right.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54652r804839_chk'
  tag severity: 'medium'
  tag gid: 'V-251217'
  tag rid: 'SV-251217r804841_rule'
  tag stig_id: 'RD6X-00-008100'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-54606r804840_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
