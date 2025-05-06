control 'SV-79883' do
  title 'The ArcGIS Server must provide audit record generation capability for DoD-defined auditable events within all application components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the application (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the application will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

'
  desc 'check', 'Review the ArcGIS Server configuration to ensure mechanisms for providing audit record generation capability for DoD-defined auditable events within application components are provided. Substitute the target environment’s values for [bracketed] variables. 

Navigate to [https://server.domain.com/arcgis]/admin/logs/settings (log on when prompted).

Verify the "Log Level" value is set to "VERBOSE".

If this value is set to any value other than "VERBOSE", this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to ensure mechanisms for providing audit record generation capability for DoD-defined auditable events within application components are provided. Substitute the target environment’s values for [bracketed] variables. 

Open "ArcGIS Server Manager" ([https://server.domain.com/arcgis]/manager) (log on when prompted).

Navigate to the "Logs" tab. Open "Settings". Change the "Log Level" value to "VERBOSE", then click "Save".'
  impact 0.7
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-65971r1_chk'
  tag severity: 'high'
  tag gid: 'V-65393'
  tag rid: 'SV-79883r1_rule'
  tag stig_id: 'AGIS-00-000026'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-71335r2_fix'
  tag satisfies: ['SRG-APP-000089', 'SRG-APP-000016', 'SRG-APP-000027', 'SRG-APP-000028', 'SRG-APP-000029', 'SRG-APP-000091', 'SRG-APP-000095', 'SRG-APP-000097', 'SRG-APP-000098', 'SRG-APP-000099', 'SRG-APP-000100', 'SRG-APP-000226', 'SRG-APP-000319', 'SRG-APP-000343', 'SRG-APP-000381', 'SRG-APP-000492', 'SRG-APP-000493', 'SRG-APP-000494', 'SRG-APP-000495', 'SRG-APP-000496', 'SRG-APP-000497', 'SRG-APP-000498', 'SRG-APP-000499', 'SRG-APP-000500', 'SRG-APP-000501', 'SRG-APP-000502', 'SRG-APP-000503', 'SRG-APP-000504', 'SRG-APP-000505', 'SRG-APP-000507', 'SRG-APP-000508', 'SRG-APP-000509', 'SRG-APP-000510']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000169', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-001487', 'CCI-001665', 'CCI-001814', 'CCI-002130', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AU-3 a', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 a', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-3 f', 'SC-24', 'CM-5 (1)', 'AC-2 (4)', 'AC-6 (9)']
end
