control 'SV-233600' do
  title 'PostgreSQL must provide the means for individuals in authorized roles to change the auditing to be performed on all application components, based on all selectable event criteria within organization-defined time thresholds.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near real time, within minutes, or within hours.'
  desc 'check', 'First, as the database administrator, check if pgaudit is present in shared_preload_libraries:

$ sudo su - postgres
$ psql -c "SHOW shared_preload_libraries"

If pgaudit is not present in the result from the query, this is a finding.'
  desc 'fix', %q(Note: The following instructions use the PGDATA, PGLOG, and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA, APPENDIX-H for PGVER, and APPENDIX-I for PGLOG.

To ensure logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

For audit logging using pgaudit is recommended. For instructions on how to setup pgaudit, see supplementary content APPENDIX-B.

As a superuser (postgres), any pgaudit parameter can be changed in postgresql.conf. Configurations can only be changed by a superuser.

### Example: Change Auditing To Log Any ROLE Statements

Note: This will override any setting already configured.

Alter the configuration to do role-based logging:

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.log = 'role'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?}

### Example: Set An Auditing Role And Grant Privileges

An audit role can be configured and granted privileges to specific tables and columns that need logging.

##### Create Test Table

$ sudo su - postgres
$ psql -c "CREATE TABLE public.stig_audit_example(id INT, name TEXT, password TEXT);"

##### Define Auditing Role

As PostgreSQL superuser (such as postgres), add the following to postgresql.conf or any included configuration files.

$ sudo su - postgres
$ vi ${PGDATA?}/postgresql.conf

Add the following parameters (or edit existing parameters):

pgaudit.role = 'auditor'

Now, as the system administrator, reload the server with the new configuration:

$ sudo systemctl reload postgresql-${PGVER?} 

Next in PostgreSQL create a new role:

postgres=# CREATE ROLE auditor;
postgres=# GRANT select(password) ON public.stig_audit_example TO auditor;

Note: This role is created with NOLOGIN privileges by default.

Now any SELECT on the column password will be logged:

$ sudo su - postgres
$ psql -c "SELECT password FROM public.stig_audit_example;"
$ cat ${PGDATA?}/${PGLOG?}/<latest_log>
< 2016-01-28 16:46:09.038 UTC bob postgres: >LOG: AUDIT: OBJECT,6,1,READ,SELECT,TABLE,public.stig_audit_example,SELECT password FROM stig_audit_example;,<none>

## Change Configurations During A Specific Timeframe

Deploy PostgreSQL that allows audit configuration changes to take effect within the timeframe required by the application owner and without involving actions or events that the application owner rules unacceptable.

Crontab can be used to do this.

For a specific audit role:

# Grant specific audit privileges to an auditing role at 5 PM every day of the week, month, year at the 0 minute mark.
0 5 * * * postgres /usr/bin/psql -c "GRANT select(password) ON public.stig_audit_example TO auditor;"
# Revoke specific audit privileges to an auditing role at 5 PM every day of the week, month, year at the 0 minute mark.
0 17 * * * postgres /usr/bin/psql -c "REVOKE select(password) ON public.stig_audit_example FROM auditor;")
  impact 0.5
  ref 'DPMS Target Crunchy Data PostgreSQL'
  tag check_id: 'C-36794r607023_chk'
  tag severity: 'medium'
  tag gid: 'V-233600'
  tag rid: 'SV-233600r617339_rule'
  tag stig_id: 'CD12-00-010000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-36759r617338_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
