control 'SV-79559' do
  title 'The DataPower Gateway must provide audit record generation capability for DoD-defined auditable events within DataPower.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., process, module). Certain specific device functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the device will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Control Panel >> View Logs

Select “DOD-EventsLog” from the drop-down list at the top of the page. If the log is empty, this is a finding.'
  desc 'fix', 'Privileged account user logon to default domain

In the search field, enter “Log Target”.

From the search results, click “Log Target”.

Click “Add”.

Name: enter the name of the log target (e.g., targetDodEvents)
Target Type: File
Log Format: XML
Timestamp format: Syslog
Destination Configuration: File Name: logstore:///dodEvents.log
Log Size: 1024
Archive Mode: Rotate
Number of Rotations: 6

Click on the “Event Filters” Tab.

Event Subscription Filter, click “Select Code”; select an Event Code from the list in the popup window.

Click the “Add” button. Repeat the process until all desired event codes have been added.

Click “Apply” to save the changes to the running configuration.

Click “Save Configuration” to save the changes to the persisted configuration.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65069'
  tag rid: 'SV-79559r1_rule'
  tag stig_id: 'WSDP-NM-000022'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-71009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
