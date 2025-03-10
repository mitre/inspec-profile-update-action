control 'SV-4298' do
  title 'Remote consoles must be disabled or protected from unauthorized access.'
  desc 'The remote console feature provides an additional means of access to the system which could allow unauthorized access if not disabled or properly secured.  With virtualization technologies, remote console access is essential as there is no physical console for virtual machines.  Remote console access must be protected in the same manner as any other remote privileged access method.'
  desc 'check', 'Check the system for configured remote consoles.  If any console port is connected to a terminal outside of a secured environment or to any aggregation device (KVM, serial concentrator), or virtualization system that does not protect the console at the level of a privileged resource in accordance with the appropriate STIGs for these devices, this is a finding.'
  desc 'fix', 'Remove the configuration for remote consoles.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8298r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4298'
  tag rid: 'SV-4298r2_rule'
  tag stig_id: 'GEN001000'
  tag gtitle: 'GEN001000'
  tag fix_id: 'F-4209r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000070']
  tag nist: ['AC-17 (4) (a)']
end
