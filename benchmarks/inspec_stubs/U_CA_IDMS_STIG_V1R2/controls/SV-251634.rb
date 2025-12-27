control 'SV-251634' do
  title 'CA IDMS CV must supply logout functionality to allow the user to implicitly terminate an external run-unit when a database request has not been made in an organizationally prescribed time frame.'
  desc %q(If a user cannot explicitly end a DBMS session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

Such logout may be explicit or implicit. Examples of explicit logouts are: clicking on a "Log Out" link or button in the application window; clicking the Windows Start button and selecting "Log Out" or "Shut Down." Examples of implicit logouts are: closing the application's (main) window; powering off the workstation without invoking the OS shutdown. 

Both the explicit and implicit logouts must be detected by the DBMS.

In all cases, the DBMS must ensure that the user's DBMS session and all processes owned by the session are terminated. 

This should not, however, interfere with batch processes/jobs initiated by the user during his/her online session: these should be permitted to run to completion.

IDMS must provide a facility by which an inactive user session may be terminated after a predetermined period of time.)
  desc 'check', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example. 

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.

Scroll through the returned text until "EXTERNAL WAIT" is found.

If the associated value is not the organization-defined timeout number of wall-clock seconds, this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 EXTERNAL WAIT is <the organization-defined timeout number of wall-clock seconds> ." where 123 is the number of the system being modified.

Enter: "GENERATE."

The change will become effective the next time the CV is stopped and started.

Note: The system EXTERNAL WAIT and can be overridden with the EXTERNAL WAIT parameter of the TASK statement.

Note: The UCFCICZ interface may also be used to clean up the CA IDMS session if access is through CICS and the CICS session has ended.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55069r807767_chk'
  tag severity: 'medium'
  tag gid: 'V-251634'
  tag rid: 'SV-251634r855272_rule'
  tag stig_id: 'IDMS-DB-000630'
  tag gtitle: 'SRG-APP-000296-DB-000306'
  tag fix_id: 'F-55023r807768_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
