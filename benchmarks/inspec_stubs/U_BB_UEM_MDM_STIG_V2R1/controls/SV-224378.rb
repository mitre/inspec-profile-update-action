control 'SV-224378' do
  title 'The BlackBerry UEM server must be configured to audit DoD or site-defined auditable events. Note: See VulDiscussion for a list of DoD required auditable events.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

DoD Required auditable events (from the MDM Protection Profile):
- Change in enrollment status
- Failure to apply policies to a mobile device
- Start up and shut down of the MDM System
- All administrative actions
- Commands issued to the MDM Agent, none]
- Specifically defined auditable events listed in Table 2 of the MDM Protection Profile

SFR ID: FAU_GEN.1.1(1), FMT_SMF.1.1(2)c.8'
  desc 'check', 'Review the list of audit events:
1.  In the UEM console go to Settings >> Infrastructure >> Audit settings
2.  Verify all required events are listed and "setting" is set to "All" for all events where this selection is available.  

Note: Events are organized by category. All events for each required event category should be selected (see the list below).

If all required events are not listed and "setting" is not set to "All" for all events where this selection is available, this is a finding.

Required events:  all "Enrollment" events, all "Policy" events, all "Server" events, all "System" related events, and all "Application" events'
  desc 'fix', 'On the BlackBerry UEM console, do the following:
1. On the menu bar, click Settings >> Infrastructure >> Audit settings.
2. In the right pane, click the edit icon.
3. To add security events to audit, click + . Select the events and click Add.
4. Select each event in each event category from the list below.
5. In the Setting column, insure "all" has been selected for each event that has this selection available. 
6. Click Save.

Required events:  all "Enrollment" events, all "Policy" events, all "Server" events, all "System" related events, and all "Application" events'
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26055r588321_chk'
  tag severity: 'medium'
  tag gid: 'V-224378'
  tag rid: 'SV-224378r604136_rule'
  tag stig_id: 'BUEM-00-000630'
  tag gtitle: 'PP-MDM-411065'
  tag fix_id: 'F-26043r588322_fix'
  tag 'documentable'
  tag legacy: ['V-102911', 'SV-111873']
  tag cci: ['CCI-000168']
  tag nist: ['AU-11']
end
