control 'SV-205466' do
  title 'The Mainframe Product must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine installation and configuration settings.

Verify data written to external security manager audit files and/or SMF records contain information that details where events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit records written to external security manager audit files and/or SMF records to contain information that details where the events occurred.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5732r299631_chk'
  tag severity: 'medium'
  tag gid: 'V-205466'
  tag rid: 'SV-205466r395727_rule'
  tag stig_id: 'SRG-APP-000097-MFP-000142'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-5732r299632_fix'
  tag 'documentable'
  tag legacy: ['SV-82735', 'V-68245']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
