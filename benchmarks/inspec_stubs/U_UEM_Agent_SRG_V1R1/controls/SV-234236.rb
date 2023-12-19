control 'SV-234236' do
  title 'The UEM Agent must generate a UEM Agent audit record of the following auditable events:-startup and shutdown of the UEM Agent-UEM policy updated-any modification commanded by the UEM Server.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

DoD Required auditable events include:
- Change in enrollment status
- Failure to apply policies to a mobile device
- Start up and shut down of the MDM System
- All administrative actions
- Commands issued to the MDM Agent.

'
  desc 'check', 'Verify the UEM Agent generates an UEM Agent audit record of the following auditable events:
-Startup and shutdown of the UEM Agent
-UEM policy updated
-any modification commanded by the UEM Server.

If the UEM Agent does not generate an UEM Agent audit record of the following auditable events:
-Startup and shutdown of the UEM Agent
-UEM policy updated
-any modification commanded by the UEM Server
this is a finding.'
  desc 'fix', 'Configure the UEM Agent to generate an UEM Agent audit record of the following auditable events:
-Startup and shutdown of the UEM Agent
-UEM policy updated
-any modification commanded by the UEM Server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37421r617389_chk'
  tag severity: 'medium'
  tag gid: 'V-234236'
  tag rid: 'SV-234236r617390_rule'
  tag stig_id: 'SRG-APP-000089-UEM-100004'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-37386r612015_fix'
  tag satisfies: ['FAU_GEN.1.1(2) Refinement']
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
