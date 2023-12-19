control 'SV-251630' do
  title 'CA IDMS must automatically terminate an external run-unit after organization-defined conditions or trigger events of time waiting to issue a database request.'
  desc 'Inactive sessions, such as a logged on user who leaves their terminal, may give a bad actor access to the system.'
  desc 'check', 'Use task SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.

Scroll through the returned text until "EXTERNAL WAIT" is found.

If the associated value is not the organization-defined timeout number of wall-clock seconds, this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained:  "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 EXTERNAL WAIT is <the organization-defined timeout number of wall-clock seconds> ." where 123 is the number of the system being modified.

Enter: "VALIDATE."

Enter: "GENERATE."

The change will become effective the next time the CV is stopped and started.

Note: The system EXTERNAL WAIT and can be overridden with the EXTERNAL WAIT parameter of the TASK statement.

Note: The UCFCICZ interface may also be used to clean up the CA IDMS session if access is through CICS and the CICS session has ended.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55065r807755_chk'
  tag severity: 'medium'
  tag gid: 'V-251630'
  tag rid: 'SV-251630r855268_rule'
  tag stig_id: 'IDMS-DB-000590'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-55019r807756_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
