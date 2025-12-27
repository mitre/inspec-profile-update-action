control 'SV-95853' do
  title 'The Central Log Server must be configured so changes made to the level and type of log records stored in the centralized repository must take effect immediately without the need to reboot or restart the application.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to respond effectively and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed; for example, in near real time, within minutes, or within hours.'
  desc 'check', 'Examine the configuration.

Verify the system is configured so changes made to the level and type of log records stored in the centralized repository take effect immediately without the need to reboot or restart the application.

If the Central Log Server is not configured so changes made to the level and type of log records stored in the centralized repository must take effect immediately without the need to reboot or restart the application, this is a finding.'
  desc 'fix', 'Configure the Central Log Server so changes made to the level and type of log records stored in the centralized repository must take effect immediately without the need to reboot or restart the application.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80799r1_chk'
  tag severity: 'low'
  tag gid: 'V-81139'
  tag rid: 'SV-95853r1_rule'
  tag stig_id: 'SRG-APP-000353-AU-000060'
  tag gtitle: 'SRG-APP-000353-AU-000060'
  tag fix_id: 'F-87913r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
