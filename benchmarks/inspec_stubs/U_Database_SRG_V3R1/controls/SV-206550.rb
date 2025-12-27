control 'SV-206550' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'Review the list of components and features installed with the database.

Use the DBMS product installation tool if supported and review the product installation documentation.

If unused components or features are installed and are not documented and authorized, this is a finding.'
  desc 'fix', 'Uninstall unused components or features that are installed and can be uninstalled. Remove any database objects and applications that are installed to support them.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6810r291318_chk'
  tag severity: 'medium'
  tag gid: 'V-206550'
  tag rid: 'SV-206550r617447_rule'
  tag stig_id: 'SRG-APP-000141-DB-000091'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6810r291319_fix'
  tag 'documentable'
  tag legacy: ['SV-42761', 'V-32424']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
