control 'SV-207539' do
  title 'A BIND 9.x server implementation must be configured to allow DNS administrators to audit all DNS server components, based on selectable event criteria, and produce audit records within all DNS server components that contain information for failed security verification tests, information to establish the outcome and source of the events, any information necessary to determine cause of failure, and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records. 

The DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

The DoD has defined the data which the application will provide an audit record generation capability for an event as the following: 

(i) Establish the source of the event;

(ii) The outcome of the event; and

(iii) Identify the application itself as the source of the event.

Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. Associating information about the source of the event within the application provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured application. 

Without information about the outcome of events, security personnel cannot make an accurate assessment about whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response."
Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.

The DNS server should be configured to generate audit records whenever a self-test fails. The OS/NDM is responsible for generating notification messages related to this audit record.

If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near real-time, within minutes, or within hours.

In addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event. In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging. In the case of centralized logging, the source would be the application name accompanied by the host or client name.

'
  desc 'check', 'Verify the name server is configured to generate audit records:

Inspect the "named.conf" file for the following:

logging {
channel channel_name {
severity info;
};
category default { channel_name; };
};

If there is no "logging" statement, this is a finding.

If the "logging" statement does not contain a "channel", this is a finding.

If the "logging" statement does not contain a "category" that utilizes a "channel", this is a finding.'
  desc 'fix', 'Configure the logging statement in the "named.conf" file: 

logging {
channel <channel_name> {
file "<file_name>";
severity info;
};
category default { <channel_name>; };
};

Replace <channel_name> and <file_name> with names that distinctively identify the purpose of the channel and the log file.

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7794r539067_chk'
  tag severity: 'low'
  tag gid: 'V-207539'
  tag rid: 'SV-207539r612253_rule'
  tag stig_id: 'BIND-9X-001010'
  tag gtitle: 'SRG-APP-000089-DNS-000004'
  tag fix_id: 'F-7794r283672_fix'
  tag satisfies: ['SRG-APP-000089-DNS-000004', 'SRG-APP-000098-DNS-000009', 'SRG-APP-000099-DNS-000010', 'SRG-APP-000226-DNS-000032', 'SRG-APP-000275-DNS-000040', 'SRG-APP-000353-DNS-000045']
  tag 'documentable'
  tag legacy: ['SV-87001', 'V-72377']
  tag cci: ['CCI-001294', 'CCI-001665', 'CCI-000133', 'CCI-000134', 'CCI-000169', 'CCI-001914']
  tag nist: ['SI-6 c', 'SC-24', 'AU-3 d', 'AU-3 e', 'AU-12 a', 'AU-12 (3)']
end
