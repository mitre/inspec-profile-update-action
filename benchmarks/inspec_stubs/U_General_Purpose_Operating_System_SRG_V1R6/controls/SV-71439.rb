control 'SV-71439' do
  title 'The operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57179'
  tag rid: 'SV-71439r1_rule'
  tag stig_id: 'SRG-OS-000363-GPOS-00150'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-62075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
