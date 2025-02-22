control 'SV-27149' do
  title 'Remote consoles must be disabled or protected from unauthorized access.'
  desc 'The remote console feature provides an additional means of access to the system which could allow unauthorized access if not disabled or properly secured.  With virtualization technologies, remote console access is essential as there is no physical console for virtual machines.  Remote console access must be protected in the same manner as any other remote privileged access method.'
  desc 'fix', 'Edit /etc/security/login.cfg and remove the alternate console definition.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-4298'
  tag rid: 'SV-27149r1_rule'
  tag stig_id: 'GEN001000'
  tag gtitle: 'GEN001000'
  tag fix_id: 'F-24423r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000070']
  tag nist: ['AC-17 (4) (a)']
end
