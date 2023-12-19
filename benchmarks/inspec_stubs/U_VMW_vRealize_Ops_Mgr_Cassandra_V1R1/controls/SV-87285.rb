control 'SV-87285' do
  title 'Unused Cassandra database components, software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'Review the Cassandra Server to ensure unused database components, software, and database objects are removed.

Open console on server Cassandra DB is hosted on and run following command: "find / | grep "cassandra"". Review the list of files displayed.

If no unused components or features are displayed, this is not a finding. Otherwise, this is a finding.'
  desc 'fix', 'Uninstall unused components or features that are installed and can be uninstalled. Remove any database objects and applications that are installed to support them.

Run the following command from Cassandra host server console:
"rm –rf <path to the unused component directory>".'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72653'
  tag rid: 'SV-87285r1_rule'
  tag stig_id: 'VROM-CS-000120'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-79057r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
