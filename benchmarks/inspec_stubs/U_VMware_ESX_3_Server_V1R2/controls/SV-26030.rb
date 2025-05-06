control 'SV-26030' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events.  Dynamic kernel modules can increase the attack surface of a system.  A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'If the system does not support dynamic kernel modules, this is not applicable.

Determine if the system is configured to audit the loading and unloading of dynamic kernel modules.  If it is not, this is a finding.'
  desc 'fix', 'Configure the system to audit the loading and unloading of dynamic kernel modules.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29213r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22383'
  tag rid: 'SV-26030r1_rule'
  tag stig_id: 'GEN002825'
  tag gtitle: 'GEN002825'
  tag fix_id: 'F-26233r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
