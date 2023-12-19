control 'SV-27148' do
  title 'Remote consoles must be disabled or protected from unauthorized access.'
  desc 'The remote console feature provides an additional means of access to the system which could allow unauthorized access if not disabled or properly secured.  With virtualization technologies, remote console access is essential as there is no physical console for virtual machines.  Remote console access must be protected in the same manner as any other remote privileged access method.'
  desc 'check', 'Check /etc/securetty
# more /etc/securetty
If the /etc/securetty file does not exist, or contains other than "console" or "/dev/null" this is a finding.'
  desc 'fix', 'If the /etc/securetty file does not exist, create the file containing only the word console and ensure correct file properties.
# echo “console” > /etc/securetty'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-28074r3_chk'
  tag severity: 'medium'
  tag gid: 'V-4298'
  tag rid: 'SV-27148r2_rule'
  tag stig_id: 'GEN001000'
  tag gtitle: 'GEN001000'
  tag fix_id: 'F-24422r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000070']
  tag nist: ['AC-17 (4) (a)']
end
