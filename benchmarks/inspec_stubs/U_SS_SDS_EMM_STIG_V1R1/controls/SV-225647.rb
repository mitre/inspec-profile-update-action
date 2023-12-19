control 'SV-225647' do
  title 'The Samsung SDS EMM must be configured to audit DoD or site-defined auditable events. Note:  See VulDiscussion for a list of DoD required auditable events.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

DoD Required auditable events (from the MDM Protection Profile):
- Change in enrollment status
- Failure to apply policies to a mobile device
- Startup and shutdown of the MDM System
- All administrative actions
- Commands issued to the MDM Agent, none]
- Specifically defined auditable events listed in Table 2 of the MDM Protection Profile

SFR ID: FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8'
  desc 'check', 'Review the event log to verify the following events are logged:
- Change in enrollment status
- Failure to apply policies to a mobile device
- Startup and shutdown of the MDM System
- All administrative actions

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Service Overview >> Log and Event >> Audit Event. 
3. Search on "Enrollment" and verify each "Console" and "Device" audit event are selected to audit Change in enrollment status.
4. Search on "Policy" and verify "Agent Policy Apply Success on a Device" (Event ID CPLC0029) and "Failed to apply Agent policy on Device" (Event ID CPLC0030) are selected to audit Failure to apply policies to a mobile device.
5. Search on "Start" and verify "Start up EMM Server" (Event ID CACS0001) is selected. Search on "shut down" and verify "Shut Down EMM Server" (Event ID CACS0002) is selected to audit startup and shutdown of the MDM System.
6. Verify all audit events with the event category of Admin Login, Administrators, Alerts, Dashboard, Device, Devices, Group, Logs, Profiles, and User Management are selected to audit all Administrative actions.

If the following required audit events have not been selected, this is a finding.
- Change in enrollment status
- Failure to apply policies to a mobile device
- Startup and shutdown of the MDM System
- All administrative actions'
  desc 'fix', 'Configure the Samsung SDS EMM to implement the required audit events.
- Change in enrollment status
- Failure to apply policies to a mobile device
- Startup and shutdown of the MDM System
- All administrative actions

On the MDM console, do the following to define audit events:
1. Log in to the Admin Console using a web browser.
2. Go to Service Overview >> Log and Event >> Audit Event. 
3. Search on "Enrollment" and select each "Console" and "Device" audit event to audit Change in enrollment status.
4. Search on "Policy" and select events "Agent Policy Apply Success on a Device" (Event ID CPLC0029) and "Failed to apply Agent policy on Device" (Event ID CPLC0030) to audit Failure to apply policies to a mobile device.
5. Search on "Start" and select event "Start up EMM Server" (Event ID CACS0001) and search on "shut down" and select event "Shut Down EMM Server" (Event ID CACS0002) to audit startup and shutdown of the MDM System.
6. Select all audit events with the event category of Admin Login, Administrators, Alerts, Dashboard, Device, Devices, Group, Logs, Profiles, and User Management to audit all Administrative actions.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27348r547726_chk'
  tag severity: 'medium'
  tag gid: 'V-225647'
  tag rid: 'SV-225647r547760_rule'
  tag stig_id: 'SSDS-00-000640'
  tag gtitle: 'PP-MDM-411065'
  tag fix_id: 'F-27336r547759_fix'
  tag 'documentable'
  tag cci: ['CCI-000168']
  tag nist: ['AU-11']
end
