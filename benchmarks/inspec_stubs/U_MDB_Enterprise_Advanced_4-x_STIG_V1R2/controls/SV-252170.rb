control 'SV-252170' do
  title 'MongoDB must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance."
  desc 'check', "Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

If the system owner, data owner, or organization requires additional assurance, this is a finding."
  desc 'fix', 'Determine the situations when a user-initiated database session  must be terminated.

Note: The  user running the  commands shown below  must have privileges with listSessions, killAnySession and impersonate action on the cluster.

In the MongoDB shell, as an authenticated user,  run the following command to list all user sessions

use config
db.system.sessions.aggregate( [  { $listSessions: { allUsers: true } } 

Reference: https://docs.mongodb.com/v4.4/reference/operator/aggregation/listSessions/

Example output:

{ "_id" : { "id" : UUID("b3b50641-54c6-4d6d-a96e-a2239fadce3c"), "uid" : BinData(0,"Y5mrDaxi8gv8RmdTsQ+1j7fmkr7JUsabhNmXAheU0fg=") }, "lastUse" : ISODate("2021-09-23T23:34:43.951Z"), "user" : { "name" : "jsmith@admin" } }

From the output identify the names of  users whose sessions should be terminated.  Using the user  for each session to be terminated, run the following command (still in MongoDB shell).

db.runCommand( { killAllSessionsByPattern: [ { users: [ { user: <user>, db: <dbname> }, ... ] }] } )

Example to terminate user "jsmith@admin" sessions from example output::

db.runCommand( { killAllSessionsByPattern: [ { users: [ { user: "jsmith", db: "admin" } ] }] } )

To terminate all user sessions running on the database, run the following command (still in MongoDB shell):

db.runCommand( { killAllSessionsByPattern: [ ] } )

Reference:
https://docs.mongodb.com/v4.4/reference/command/killAllSessionsByPattern/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55626r813890_chk'
  tag severity: 'medium'
  tag gid: 'V-252170'
  tag rid: 'SV-252170r855507_rule'
  tag stig_id: 'MD4X-00-004400'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-55576r813891_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
