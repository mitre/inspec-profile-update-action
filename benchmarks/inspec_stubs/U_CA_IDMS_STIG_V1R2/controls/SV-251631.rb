control 'SV-251631' do
  title 'CA IDMS must automatically terminate a task or session after organization-defined conditions or trigger events of time waiting to get a resource and/or time of inactivity.'
  desc "A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance.

It may be desired to limit the amount of time a task can wait for a resource before terminating it."
  desc 'check', 'Use task SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.

Scroll through the returned text until "INACTIVE INTERVAL" is found.

If the associated value is not the organization-defined timeout number of wall-clock seconds, this is a finding.

Scroll through the returned text until "RUNAWAY INTERVAL" is found.

If the associated value is not the organization-defined timeout number of wall-clock seconds, this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained:  "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 INACTIVE INTERVAL is <the organization-defined timeout number of wall-clock seconds> ." where 123 is the number of the system being modified.

Enter: "MODIFY SYSTEM 123 RUNAWAY INTERVAL is <the organization-defined timeout number of wall-clock seconds> ." where 123 is the number of the system being modified.

Enter: "VALIDATE."

Enter: "GENERATE."

The change will become effective the next time the CV is stopped and started.

Note: The system INACTIVE INTERVAL can be overridden with the INACTIVE INTERVAL TASK parameters, e.g., for task RHDCNP3S which services external tasks/sessions.

Note: The UCFCICZ interface may also be used to clean up the CA IDMS session if access is through CICS and the CICS session has ended.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55066r807758_chk'
  tag severity: 'medium'
  tag gid: 'V-251631'
  tag rid: 'SV-251631r855269_rule'
  tag stig_id: 'IDMS-DB-000600'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-55020r807759_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
