control 'SV-233263' do
  title 'The container platform must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'The container platform and its components must generate audit records when successful and unsuccessful logon attempts occur. The information system can determine if an account is compromised or is in the process of being compromised and can take actions to thwart the attack. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.'
  desc 'check', 'Review the container platform configuration for audit logon events. 

Ensure audit policy for successful and unsuccessful logon events are enabled. 

Verify events are written to the log. 

Validate system documentation is current. 

If logon attempts do not generate log records, this is a finding.'
  desc 'fix', 'Configure the container platform registry, keystore, and runtime to generate audit log for successful and unsuccessful logon for any all accounts and services. Revise all applicable system documentation.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36199r601882_chk'
  tag severity: 'medium'
  tag gid: 'V-233263'
  tag rid: 'SV-233263r879874_rule'
  tag stig_id: 'SRG-APP-000503-CTR-001275'
  tag gtitle: 'SRG-APP-000503'
  tag fix_id: 'F-36167r601277_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
