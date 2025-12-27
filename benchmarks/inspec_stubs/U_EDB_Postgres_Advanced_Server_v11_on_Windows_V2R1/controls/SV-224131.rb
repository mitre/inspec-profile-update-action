control 'SV-224131' do
  title 'The EDB Postgres Advanced Server must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed.

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

The EDB Postgres Advanced Server must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy.

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', 'Verify that the Postgres host-based authentication file (i.e., pg_hba.conf) has been configured so that database users are authenticated using credentials supplied by the organization-level authentication/access system. If it has been configured correctly, this is not a finding.

Actions to verify:
 Verify none of the uncommented entries in the pg_hba.conf include: "trust", "sha-256-scram", "md5", "ident", "peer”, or "password" as allowable access methods.
Verify options are set to the correct values for the specific environment.

Note: The default location for the pg_hba.conf file is in the postgresql data directory. The location of the pg_hba.conf file for a running postgres instance can be found using the following command run from a Windows command prompt:

 psql -d <database name> -U <database superuser name> -c "SHOW hba_file"

where, <database name> is any database in the EDB postgres instance and <database superuser name> is a database superuser. By default, a database named "edb" and a superuser named "enterprisedb" are installed with EDB Postgres Advanced Server (EPAS).

To verify the pg_hba.conf file is not using the access methods listed above, open the pg_hba.conf file in a text editor and inspect the contents of the file, looking for uncommented lines with these methods. Optionally, the following command can be run from a Windows command prompt to identify any uncommented lines in the pg_hba.conf file that may be using these methods: 

 type <postgresql pg_hba.conf directory>\\pg_hba.conf | findstr /N "scram-sha-256 md5 trust password peer ident" | find /V /N "#"

Note: For the command above, if the path to the pg_hba.conf file contains spaces in it, the path to the file (including the file name) must be placed in double quotes. 

If any uncommented lines are identified, verify that the users are documented as being authorized to use one of these access methods.

If the users are not authorized to use these access methods, this is a finding.'
  desc 'fix', 'Identify any user using "trust", "sha-256-scram", md5", "ident", "peer" or "password" as allowable access methods.

To identify users in the pg_hba.conf file using the methods listed above, open the pg_hba.conf file in a text editor, and inspect the contents of the file, looking for uncommented lines with these methods. Optionally, the following command can be run from a Windows command prompt to identify any uncommented lines in the pg_hba.conf file that may be using these methods: 

 type <postgresql pg_hba.conf directory>\\pg_hba.conf | findstr /N "scram-sha-256 md5 trust password peer ident" | find /V /N "#"

Note: If the path to the pg_hba.conf file contains spaces in it, the path to the file (including the file name) should be placed in double quotes.

Document any rows that have "trust", "sha-256-scram", "md5", "ident", "peer”, or "password" specified for the "METHOD" column and obtain appropriate approval for each user specified in the "USER" column (i.e., all DBMS managed accounts).

For any users not documented and approved as DBMS managed accounts, change the "METHOD" column to one of the externally managed (not "trust", "sha-256-scram", "md5", "ident", "peer" or "password") options defined here:

https://www.postgresql.org/docs/current/static/auth-methods.html'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25804r495413_chk'
  tag severity: 'medium'
  tag gid: 'V-224131'
  tag rid: 'SV-224131r508023_rule'
  tag stig_id: 'EP11-00-000700'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-25792r495414_fix'
  tag 'documentable'
  tag legacy: ['SV-109393', 'V-100289']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
