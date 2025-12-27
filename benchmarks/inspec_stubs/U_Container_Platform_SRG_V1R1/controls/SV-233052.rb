control 'SV-233052' do
  title 'The container platform components must provide the ability to send audit logs to a central enterprise repository for review and analysis.'
  desc 'The container platform components must send audit events to a central managed audit log repository to provide reporting, analysis, and alert notification. Incident response relies on successful timely, accurate system analysis in order for the organization to identify and respond to possible security events.'
  desc 'check', 'Review the configuration settings to determine if the container platform components are configured to send audit events to central managed audit log repository. 

If the container platform is not configured to send audit events to central managed audit log repository, this is a finding.'
  desc 'fix', 'Configure the container platform components to send audit logs to a central managed audit log repository.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35988r599546_chk'
  tag severity: 'medium'
  tag gid: 'V-233052'
  tag rid: 'SV-233052r599547_rule'
  tag stig_id: 'SRG-APP-000111-CTR-000220'
  tag gtitle: 'SRG-APP-000111'
  tag fix_id: 'F-35956r598793_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
