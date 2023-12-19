control 'SV-233265' do
  title 'The container platform audit records must record user access start and end times.'
  desc 'The container platform must generate audit records showing start and end times for users and services acting on behalf of a user accessing the registry and keystore. These components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.'
  desc 'check', 'Review the container platform configuration for audit user access start and end times. 

Ensure audit policy for user access start and end times are enabled. 

Verify events are written to the log. 

Validate system documentation is current. 

If user access start and end times do not generate log records, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit log for user access start and end times for any all accounts and services. Revise all applicable system documentation.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36201r601839_chk'
  tag severity: 'medium'
  tag gid: 'V-233265'
  tag rid: 'SV-233265r879876_rule'
  tag stig_id: 'SRG-APP-000505-CTR-001285'
  tag gtitle: 'SRG-APP-000505'
  tag fix_id: 'F-36169r601283_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
