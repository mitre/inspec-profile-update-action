control 'SV-87283' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the DBMS, etc.) must be restricted to authorized users.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review the Cassandra Server settings to ensure the role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the DBMS, etc.) are restricted to authorized users.

At the command prompt, execute the following command:

# find /usr/lib/vmware-vcops/cassandra -type f ! \\( -user admin -o -user root \\)

If any files are listed that are not owned by either "admin" or "root", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to restrict the role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the DBMS, etc.) to authorized users.

At the command line execute the following command:

# chown root <file>

Replace <file> with the files that are not owned by either "admin" or "root".'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72651'
  tag rid: 'SV-87283r1_rule'
  tag stig_id: 'VROM-CS-000110'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-79055r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
