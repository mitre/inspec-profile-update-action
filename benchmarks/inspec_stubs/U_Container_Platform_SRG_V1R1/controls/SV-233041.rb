control 'SV-233041' do
  title 'The container platform must initiate session auditing upon startup.'
  desc 'When the container platform is started, container platform components and user services can also be started. It is important that the container platform begin auditing on startup in order to handle container platform startup events along with events for container platform components and services that begin on startup.'
  desc 'check', 'Review the container platform configuration for session audits. 

Ensure audit policy for session logging at startup is enabled. 

Verify events are written to the log. 

Validate system documentation is current. 

If the container platform is not configured to meet this requirement, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit logs for session logging at startup. Revise all applicable system documentation.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35977r599713_chk'
  tag severity: 'medium'
  tag gid: 'V-233041'
  tag rid: 'SV-233041r599714_rule'
  tag stig_id: 'SRG-APP-000092-CTR-000165'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-35945r598760_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
