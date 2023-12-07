control 'SV-233534' do
  title 'PostgreSQL must allow only the Information System Security Manager (ISSM), or individuals or roles appointed by the ISSM, to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Note: The following instructions use the PGDATA environment variable. See supplementary content APPENDIX-F for instructions on configuring PGDATA.

Check PostgreSQL settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.

As the database administrator (shown here as "postgres"), verify the permissions for PGDATA:

$ ls -la ${PGDATA?}

If anything in PGDATA is not owned by the database administrator, this is a finding.

Next, as the database administrator, run the following SQL:

$ sudo su - postgres
$ psql -c "\\du"

Review the role permissions, if any role is listed as superuser but should not have that access, this is a finding.'
  desc 'fix', "Configure PostgreSQL's settings to allow designated personnel to select which auditable events are audited.

Using pgaudit allows administrators the flexibility to choose what they log. For an overview of the capabilities of pgaudit, see https://github.com/pgaudit/pgaudit. 

See supplementary content APPENDIX-B for documentation on installing pgaudit.

See supplementary content APPENDIX-C for instructions on enabling logging. Only administrators/superuser can change PostgreSQL configurations. Access to the database administrator must be limited to designated personnel only.

To ensure that postgresql.conf is owned by the database owner:

$ chown postgres:postgres ${PGDATA?}/postgresql.conf
$ chmod 600 ${PGDATA?}/postgresql.conf"
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36728r606825_chk'
  tag severity: 'medium'
  tag gid: 'V-233534'
  tag rid: 'SV-233534r606827_rule'
  tag stig_id: 'CD12-00-002600'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-36693r606826_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
