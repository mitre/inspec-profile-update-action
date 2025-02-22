control 'SV-79661' do
  title 'The DataPower Gateway must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Go to Administration-Miscellaneous >> Manage Log Targets, Event Subscription Tab and check for acceptable configuration in the name and category fields. Go to the Main tab and check for the desired values in the protocol field.

If no Log Targets are configured, this is a finding.'
  desc 'fix', 'Use the CLI copy command. Syntax: copy -f sourceURL destinationURL
-f is an optional switch that forces an unconditional copy. Example: xi52(config)# copy audit:audit-log sftp://test@xx.xx.x.xxx/LOGS/x/Week1.log. 

Or, go to Administration-Miscellaneous >> Manage Log Targets, Event Subscription Tab, provide a name, press Add, choose Category “audit”. 

Go to Main tab, choose protocol (NFS, SMTP, SNMP, File, etc.) and configure.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65171'
  tag rid: 'SV-79661r1_rule'
  tag stig_id: 'WSDP-NM-000128'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-71111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
