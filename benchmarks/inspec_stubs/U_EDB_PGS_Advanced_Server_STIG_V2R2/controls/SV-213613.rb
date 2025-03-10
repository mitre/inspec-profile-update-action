control 'SV-213613' do
  title 'The EDB Postgres Advanced Server must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance."
  desc 'check', "Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

If the documentation requires automatic session termination but the DBMS is not configured via triggers, scripts, or other organization-defined manners to terminate sessions when required, this is a finding."
  desc 'fix', "Execute this SQL command in the places where the documentation requires automatic session termination:

SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE usename = '<username>'"
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14835r290151_chk'
  tag severity: 'medium'
  tag gid: 'V-213613'
  tag rid: 'SV-213613r508024_rule'
  tag stig_id: 'PPS9-00-006700'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-14833r290152_fix'
  tag 'documentable'
  tag legacy: ['SV-83583', 'V-68979']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
