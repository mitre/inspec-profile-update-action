control 'SV-221910' do
  title 'The Central Log Server must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality. 

Associating information about where the event occurred within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server produces audit records containing information to establish where the events occurred.

If the Central Log Server is not configured to produce audit records containing information to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to produce audit records containing information to establish where the events occurred.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23625r420072_chk'
  tag severity: 'low'
  tag gid: 'V-221910'
  tag rid: 'SV-221910r420074_rule'
  tag stig_id: 'SRG-APP-000097-AU-000700'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-23614r420073_fix'
  tag 'documentable'
  tag legacy: ['SV-109153', 'V-100049']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
