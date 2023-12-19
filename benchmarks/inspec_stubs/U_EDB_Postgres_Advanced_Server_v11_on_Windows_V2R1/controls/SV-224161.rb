control 'SV-224161' do
  title 'Unused database components, EDB Postgres Advanced Server software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'Open Control Program >> Programs >> Programs and Features. Look specifically for publishers of EnterpriseDB, pgAdmin, or PostgreSQL. If any programs are installed which are not documented as needed by the government program, this is a finding.'
  desc 'fix', 'Open Control Program >> Programs >> Programs and Features. Select any programs that should not be installed, click "uninstall", and then follow the prompts to uninstall the software.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25834r495501_chk'
  tag severity: 'medium'
  tag gid: 'V-224161'
  tag rid: 'SV-224161r508023_rule'
  tag stig_id: 'EP11-00-003800'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-25822r495502_fix'
  tag 'documentable'
  tag legacy: ['V-100349', 'SV-109453']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
