control 'SV-240295' do
  title 'The vRA PostgreSQL database must limit modify privileges to authorized accounts.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "\\du;"

If the accounts other than "postgres" and "vcac_replication" have "create" privileges, this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "REVOKE ALL PRIVILEGES FROM <user>;"

Replace <user> with the account discovered during the check.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43528r668727_chk'
  tag severity: 'medium'
  tag gid: 'V-240295'
  tag rid: 'SV-240295r668729_rule'
  tag stig_id: 'VRAU-PG-000140'
  tag gtitle: 'VRAU-PG-000140'
  tag fix_id: 'F-43487r668728_fix'
  tag 'documentable'
  tag legacy: ['SV-100017', 'V-89367']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
