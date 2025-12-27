control 'SV-234323' do
  title 'The UEM server must provide audit record generation capability for DoD-defined auditable events within all application components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

DoD Required auditable events:
- Change in enrollment status
- Failure to apply policies to a mobile device
- Start up and shut down of the UEM System
- All administrative actions
- Commands issued to the UEM Agent
- Server component failure
- All system alerts, including system integrity verification failures 

Satisfies:FAU_ALT_EXT.1.1, FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8 
Reference:PP-MDM-411065, PP-MDM-412000'
  desc 'check', 'Verify the UEM server provides audit record generation capability for DoD-defined auditable events within all application components.

If the UEM server does not provide audit record generation capability for DoD-defined auditable events within all application components, this is a finding.'
  desc 'fix', 'Configure the UEM server to provide audit record generation capability for DoD-defined auditable events within all application components.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37508r613979_chk'
  tag severity: 'medium'
  tag gid: 'V-234323'
  tag rid: 'SV-234323r879559_rule'
  tag stig_id: 'SRG-APP-000089-UEM-000049'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-37473r613980_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
