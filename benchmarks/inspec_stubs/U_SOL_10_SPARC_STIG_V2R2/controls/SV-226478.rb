control 'SV-226478' do
  title 'Remote consoles must be disabled or protected from unauthorized access.'
  desc 'The remote console feature provides an additional means of access to the system which could allow unauthorized access if not disabled or properly secured.  With virtualization technologies, remote console access is essential as there is no physical console for virtual machines.  Remote console access must be protected in the same manner as any other remote privileged access method.'
  desc 'check', 'Verify no auxiliary consoles are defined.
# consadm -p
If any output is generated, this is a finding.'
  desc 'fix', 'Remove each auxiliary console.
# consadm -d <console device>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28639r482819_chk'
  tag severity: 'medium'
  tag gid: 'V-226478'
  tag rid: 'SV-226478r603265_rule'
  tag stig_id: 'GEN001000'
  tag gtitle: 'SRG-OS-000297'
  tag fix_id: 'F-28627r482820_fix'
  tag 'documentable'
  tag legacy: ['V-4298', 'SV-27147']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
