control 'SV-80365' do
  title 'Trend Deep Security must provide audit record generation capability for DoD-defined auditable events within all application components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit record generation capability for DoD-defined auditable events within all application components is provided.

Verify the Administration >> System Settings >> System Events, are set to “Record.”
- capture successful and unsuccessful logon attempts,
- privileged activities or other system level access,
- starting and ending time for user access to the system
- concurrent logons from different workstations
- successful and unsuccessful accesses to objects
- all program initiations,
- all direct access to the information system, 
- all account creation, modification, disabling, and termination actions.

If these settings are not set to “Record”, this is a finding.'
  desc 'fix', 'Configure Trend Deep Security to provide audit record generation capability for DoD-defined auditable events within all application components.

Go to Administration >> System Settings >> System Events, and set the following settings to “Record.”
160 Authentication Failed
600 User Signed In
601 User Signed Out
602 User Timed Out
603 User Locked Out
604 User Unlocked
608 User Session Validation Failed
609 User Made Invalid Request
610 User Session Validated
611 User Viewed Firewall Event
613 User Viewed Intrusion Prevention Event
615 User Viewed System Event
616 User Viewed Integrity Monitoring Event
617 User Viewed Log Inspection Event
618 User Viewed Quarantined File Detail
619 User Viewed Anti-Malware Event
620 User Viewed Web Reputation Event
621 User Signed In As Tenant
650 User Created
651 User Deleted
652 User Updated
653 User Password Set
660 Role Created
661 Role Deleted
662 Role Updated
702 Credentials Generated
703 Credential Generation Failed'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66523r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65875'
  tag rid: 'SV-80365r1_rule'
  tag stig_id: 'TMDS-00-000060'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-71951r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
