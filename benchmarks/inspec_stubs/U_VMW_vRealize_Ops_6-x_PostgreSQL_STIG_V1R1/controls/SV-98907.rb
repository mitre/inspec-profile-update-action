control 'SV-98907' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the vROps PostgreSQL DB, etc.) must be restricted to authorized users.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "\\du;"

If the accounts other than "postgres" and "vc" have create privileges, this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "REVOKE ALL PRIVILEGES FROM <user>;"

Replace <user> with the account discovered during the check.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88257'
  tag rid: 'SV-98907r1_rule'
  tag stig_id: 'VROM-PG-000155'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-94999r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
