control 'SV-251632' do
  title 'CA IDMS CV must supply logout functionality to allow the user to implicitly terminate a session initiated by the terminal user.'
  desc 'If a user does not sign off a terminal after use, it can be used for illegitimate purposes. The IDMS RESOURCE TIMEOUT INTERVAL allows the organization to set a limit to the amount of time it can be left unattended.'
  desc 'check', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch. 

Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example. 

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.

Scroll through the returned text until "RESOURCE TIMEOUT INTERVAL" is found.

If the associated value is not the organization-defined timeout number of wall-clock seconds, this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 RESOURCE TIMEOUT INTERVAL is <the organization-defined timeout number of wall-clock seconds> ." where 123 is the number of the system being modified.

Enter: "GENERATE."

The change will become effective the next time the CV is stopped and started.

Note: The system RESOURCE TIMEOUT INTERVAL can be overridden with the TASK RESOURCE TIMEOUT INTERVAL for individual tasks.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55067r807761_chk'
  tag severity: 'medium'
  tag gid: 'V-251632'
  tag rid: 'SV-251632r807763_rule'
  tag stig_id: 'IDMS-DB-000610'
  tag gtitle: 'SRG-APP-000296-DB-000306'
  tag fix_id: 'F-55021r807762_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
