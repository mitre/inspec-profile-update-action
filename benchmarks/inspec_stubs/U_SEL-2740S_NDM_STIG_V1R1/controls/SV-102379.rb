control 'SV-102379' do
  title 'The SEL-2740S must be configured to create log records for DoD-defined events.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., process, module). Certain specific device functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the device will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);
(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and
(iii) All account creation, modification, disabling, and termination actions.'
  desc 'check', %q(Ensure SEL-2740S Syslog servers are configured by doing the following:
1. Log in with Permission Level 3 rights into parent OTSDN Controller.
2. Go to the "Configuration Objects" page and select the switch.
3. Check Syslog Server IP addresses are in the settings fields configured for the log services.
4. Check Syslog flows exist and are accurate for the SEL-2740S DUT and additional neighbor devices' flows exist and are correct.

If the SEL-2740S is not configured with Syslog server entries to ensure auditability, this is a finding.)
  desc 'fix', 'To configure the SEL-2740S to send logs to Syslog servers do the following:
1. Log in with Permission Level 3 right into parent OTSDN Controller.
2. Go to the "Configuration Objects" settings page and select the desired switch for SEL-2740S node.
3. Insert the Syslog log service and configure the settings with the desired Server IP addresses into the Syslog settings fields.
4. Create the flow rules necessary for Syslog.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91587r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92291'
  tag rid: 'SV-102379r1_rule'
  tag stig_id: 'SELS-ND-000230'
  tag gtitle: 'SRG-APP-000089-NDM-000221'
  tag fix_id: 'F-98529r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
