control 'SV-77423' do
  title 'Riverbed Optimization System (RiOS) must provide audit record generation capability for DoD-defined auditable events within the network device.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., process, module). Certain specific device functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the device will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', %q(Verify that RiOS is configured to off-load audit records (logs) onto a different system than the system being audited.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Logging
Verify that "Remote Log Servers" contains IP addresses for all available log servers

View "Per-Process Logging" section to see if a process or severity has been configured. Note: This only affects the system log, not the user type facilities.

If a filter has been added in 'Per-Process Logging" which prevents the capture of DoD-defined auditable events, this is a finding.

If "Remote Log Servers" is empty and no remote log servers are configured, this is a finding.)
  desc 'fix', 'Configure RiOS to off-load audit records onto a different system than the system being audited.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Logging
Click on "Add a New Log Server"
Set "Server IP" to the IP address of the remote log server
Set "Minimum Severity" to Info
In the Pre-Process Logging area, Click Remote Selected if any of the filtered processes violate the capture of DoD-defined auditable events.
Click "Add"
Click "Apply"

Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63685r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62933'
  tag rid: 'SV-77423r1_rule'
  tag stig_id: 'RICX-DM-000071'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-68851r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
