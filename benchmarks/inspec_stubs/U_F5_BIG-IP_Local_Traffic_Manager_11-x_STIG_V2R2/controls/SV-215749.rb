control 'SV-215749' do
  title 'The BIG-IP Core implementation must be configured to protect audit information from unauthorized read access.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured network element. Thus, it is imperative that the collected log data from the various network elements, as well as the auditing tools, be secured and can only be accessed by authorized personnel.'
  desc 'check', "Verify the BIG-IP Core is configured to protect audit information from unauthorized read access.

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Under 'Log Access', verify unauthorized roles are set to 'Deny'.

If the BIG-IP Core is not configured to protect audit information from unauthorized read access, this is a finding."
  desc 'fix', 'Configure the BIG-IP Core to protect audit information from unauthorized read access.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16941r291060_chk'
  tag severity: 'medium'
  tag gid: 'V-215749'
  tag rid: 'SV-215749r557356_rule'
  tag stig_id: 'F5BI-LT-000055'
  tag gtitle: 'SRG-NET-000098-ALG-000056'
  tag fix_id: 'F-16939r291061_fix'
  tag 'documentable'
  tag legacy: ['SV-74709', 'V-60279']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
