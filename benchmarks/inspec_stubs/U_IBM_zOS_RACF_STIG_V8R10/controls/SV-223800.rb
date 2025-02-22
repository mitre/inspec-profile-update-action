control 'SV-223800' do
  title 'IBM z/OS system administrator must develop a procedure to notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Ask the system administrator for the procedure to notify designated personnel if baseline configurations are changed in an unauthorized manner.

If there is no procedure, this is a finding.'
  desc 'fix', 'Develop a procedure to notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25473r515088_chk'
  tag severity: 'medium'
  tag gid: 'V-223800'
  tag rid: 'SV-223800r853626_rule'
  tag stig_id: 'RACF-OS-000460'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-25461r515089_fix'
  tag 'documentable'
  tag legacy: ['SV-107411', 'V-98307']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
