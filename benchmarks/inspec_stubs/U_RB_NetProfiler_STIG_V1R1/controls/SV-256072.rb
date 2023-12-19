control 'SV-256072' do
  title 'The Riverbed NetProfiler must be configured to automatically generate DOD-required audit records with sufficient information to support incident reporting to a central log server.'
  desc 'Auditing can be disabled in the NetProfiler. The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. Upon gaining access to a network device, an attacker often attempts to create or change accounts to ensure continued access. Audit records and alerts with sufficient information to provide the information system security officer (ISSO) with forensic information about the incident can alert administrators to an ongoing attack attempt.

The Riverbed NetProfiler audit log generates sufficient information by default to fulfill DOD requirements when the audit setting "Log all Audit Events" is selected. Sites may also fine-tune using the "Log custom set of audit events" and selecting applicable settings; however, this method may fail to capture all required audit records.

'
  desc 'check', 'Enable all DOD-required audit requirements, including changes to user accounts and use of privileged functions.

Go to Administration >> Audit Trail. 

Click "Audit Settings". 

Check under "Logging Settings". 

If "Log all Audit Events" is not selected, this is a finding.'
  desc 'fix', 'Go to Administration >> Audit Trail. 

Click "Audit Settings". 

Under "Logging Settings", select "Log all Audit Events". 

Click "OK" to save the settings.'
  impact 0.7
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59746r882722_chk'
  tag severity: 'high'
  tag gid: 'V-256072'
  tag rid: 'SV-256072r882724_rule'
  tag stig_id: 'RINP-DM-000004'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-59689r882723_fix'
  tag satisfies: ['SRG-APP-000026-NDM-000208', 'SRG-APP-000516-NDM-000350', 'SRG-APP-000027-NDM-000209', 'SRG-APP-000028-NDM-000210', 'SRG-APP-000029-NDM-000211', 'SRG-APP-000092-NDM-000224', 'SRG-APP-000095-NDM-000225', 'SRG-APP-000096-NDM-000226', 'SRG-APP-000097-NDM-000227', 'SRG-APP-000098-NDM-000228', 'SRG-APP-000099-NDM-000229', 'SRG-APP-000100-NDM-000230', 'SRG-APP-000101-NDM-000231', 'SRG-APP-000381-NDM-000305', 'SRG-APP-000080-NDM-000220', 'SRG-APP-000091-NDM-000223', 'SRG-APP-000343-NDM-000289', 'SRG-APP-000495-NDM-000318', 'SRG-APP-000499-NDM-000319', 'SRG-APP-000503-NDM-000320', 'SRG-APP-000504-NDM-000321']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000166', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-001464', 'CCI-001487', 'CCI-001814', 'CCI-002234', 'CCI-002605']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-10', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-14 (1)', 'AU-3 f', 'CM-5 (1)', 'AC-6 (9)', 'SI-2 c']
end
