control 'SV-233043' do
  title 'The container platform audit records must have a date and time association with all events.'
  desc 'Within the container platform, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues, such as security incidents, that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to know when the event occurred. To establish the time of the event, the audit record must contain the date and time.'
  desc 'check', 'Review the container platform configuration for audit events date and time. 

Ensure audit policy for event date and time are enabled. 

Verify records showing event date and time are included in the log. 

Validate system documentation is current. 

If the date and time are not included, this is a finding.'
  desc 'fix', 'Configure the container platform to include log date and time with the event. Revise all applicable system documentation.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35979r601622_chk'
  tag severity: 'medium'
  tag gid: 'V-233043'
  tag rid: 'SV-233043r879564_rule'
  tag stig_id: 'SRG-APP-000096-CTR-000175'
  tag gtitle: 'SRG-APP-000096'
  tag fix_id: 'F-35947r600617_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
