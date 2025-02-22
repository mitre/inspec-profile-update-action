control 'SV-239209' do
  title 'VMware Postgres must not allow schema access to unauthorized accounts.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database management systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "\dp .*.;"/opt/vmware/vpostgres/current/bin/psql -U postgres -c "\dp .*.;"|grep -E "information_schema|pg_catalog"|awk -F '|' '{print $4}'|awk -F '/' '{print $1}'|grep -v "=r"|grep -v "postgres"|grep -v "  "

If any lines are returned, this is a finding.)
  desc 'fix', 'At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "REVOKE ALL PRIVILEGES ON <name> FROM <user>;"

Replace <name> and <user> with the Access Privilege name and account, respectively, discovered during the check.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42442r678998_chk'
  tag severity: 'medium'
  tag gid: 'V-239209'
  tag rid: 'SV-239209r679000_rule'
  tag stig_id: 'VCPG-67-000017'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-42401r678999_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
