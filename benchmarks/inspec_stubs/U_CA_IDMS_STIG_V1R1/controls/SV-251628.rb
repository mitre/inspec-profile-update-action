control 'SV-251628' do
  title 'CA IDMS must automatically terminate a terminal session after organization-defined conditions or trigger events of terminal inactivity time.'
  desc "A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance.

If a user does not sign off a terminal after use it can be used for illegitimate purposes. The IDMS RESOURCE TIMEOUT INTERVAL allows the organization to set a limit to the amount of time it can be left unattended."
  desc 'check', 'Use task SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.
Scroll through the returned text until "RESOURCE TIMEOUT INTERVAL" is found.

If the associated value is not the organization-defined timeout number of wall-clock seconds, this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained:  "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 RESOURCE TIMEOUT INTERVAL is <the organization-defined timeout number of wall-clock seconds> ." where 123 is the number of the system being modified.

Enter: "VALIDATE."

Enter: "GENERATE.

The change will become effective the next time the CV is stopped and started.

Note: The system RESOURCE TIMEOUT INTERVAL can be overridden with the TASK RESOURCE TIMEOUT INTERVAL for individual tasks.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55063r807749_chk'
  tag severity: 'medium'
  tag gid: 'V-251628'
  tag rid: 'SV-251628r807751_rule'
  tag stig_id: 'IDMS-DB-000570'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-55017r807750_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
