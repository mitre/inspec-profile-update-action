control 'SV-213562' do
  title 'The EDB Postgres Advanced Server must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

The DBMS must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', 'Verify that pg_hba.conf is not using: “trust”, “md5”, or “password” as allowable access methods.

> cat <postgresql data directory>/pg_hba.conf | egrep –I ‘(trust|md5|password)’ | grep –v ‘#’

If any output is produced, verify the users are documented as being authorized to use one of these access methods.

If the users are not authorized to use these access methods, this is a finding.

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  desc 'fix', 'Identify any user that is using “trust”, “md5”, or “password” as allowable access methods.

> cat <postgresql data directory>/pg_hba.conf | egrep –I ‘(trust|md5|password)’ | grep –v ‘#’

Document any rows that have "trust", "md5", or "password" specified for the "METHOD" column and obtain appropriate approval for each user specified in the "USER" column (i.e., all DBMS managed accounts).

For any users that are not documented and approved as DBMS managed accounts, change the "METHOD" column to one of the externally managed (not "trust", "md5", or "password") options defined here:

http://www.postgresql.org/docs/9.5/static/auth-methods.html

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14784r289998_chk'
  tag severity: 'high'
  tag gid: 'V-213562'
  tag rid: 'SV-213562r836836_rule'
  tag stig_id: 'PPS9-00-000700'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-14782r289999_fix'
  tag 'documentable'
  tag legacy: ['SV-83481', 'V-68877']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
