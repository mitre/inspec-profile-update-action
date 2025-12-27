control 'SV-91177' do
  title 'The Akamai Luna Portal must provide audit record generation capability for DoD-defined auditable events within the network device.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., process, module). Certain specific device functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the device will provide an audit record generation capability as the following:

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful login attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logins from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click on the DoD-defined auditable events individually.
5. Verify that the applicable events are selected by clicking the "Settings" button.

If the Luna Control Center event notifications are not enabled, this is a finding.'
  desc 'fix', 'Enable Luna Event notifications.

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Click the "Create New Alert" button.
4. Select "Luna Control Center Event" and press the "Next" button.
5. Check each of the applicable boxes for the DoD-defined auditable events.
6. Proceed through the alert creation wizard, filling out the appropriate fields, and then click "Submit".'
  impact 0.3
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76141r1_chk'
  tag severity: 'low'
  tag gid: 'V-76481'
  tag rid: 'SV-91177r1_rule'
  tag stig_id: 'AKSD-DM-000020'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-83159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
