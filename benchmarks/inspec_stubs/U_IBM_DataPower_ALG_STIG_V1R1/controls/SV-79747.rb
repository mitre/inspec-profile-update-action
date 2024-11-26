control 'SV-79747' do
  title 'The DataPower Gateway must be configured to support centralized management and configuration.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

Network components requiring centralized audit log management must have the capability to support centralized management.

The DoD requires centralized management of all network component audit record content.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'In default domain >> Search Bar “SNMP Settings”.

If SNMP object is disabled, this is a finding.'
  desc 'fix', 'In default domain >> Search Bar “SNMP Settings” >> Enterprise MIBs tab >> Download and store all DataPower MIBs >> Trap and Notification Targets tab >> Add >> Remote Hosts Address host address >> Remote Port port >> Versions snmp version >> Apply >> Apply >> Save Configuration.

If the only log target is “default-log”: Type “Log Target” in the Search field >> Log target >> Main tab>>Target Type “syslog” >> syslog Facility facility >> Local Identifier identifier >> Remote Host hostname.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65257'
  tag rid: 'SV-79747r1_rule'
  tag stig_id: 'WSDP-AG-000089'
  tag gtitle: 'SRG-NET-000333-ALG-000049'
  tag fix_id: 'F-71197r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
