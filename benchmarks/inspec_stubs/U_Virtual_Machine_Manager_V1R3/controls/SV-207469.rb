control 'SV-207469' do
  title 'The VMM must notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  desc "Unauthorized changes to the baseline configuration could make the VMM vulnerable to various attacks or allow unauthorized access to the VMM. Changes to VMM configurations can have unintended side effects, some of which may be relevant to security. 

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the VMM. The VMM's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify the VMM notifies designated personnel if baseline configurations are changed in an unauthorized manner.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7726r365811_chk'
  tag severity: 'medium'
  tag gid: 'V-207469'
  tag rid: 'SV-207469r854642_rule'
  tag stig_id: 'SRG-OS-000363-VMM-001400'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-7726r365812_fix'
  tag 'documentable'
  tag legacy: ['V-57139', 'SV-71399']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
