control 'SV-37376' do
  title 'Remote consoles must be disabled or protected from unauthorized access.'
  desc 'The remote console feature provides an additional means of access to the system which could allow unauthorized access if not disabled or properly secured.  With virtualization technologies, remote console access is essential as there is no physical console for virtual machines.  Remote console access must be protected in the same manner as any other remote privileged access method.'
  desc 'check', 'Check /etc/securetty
# more /etc/securetty
If the file does not exist, or contains more than "console" or a single "tty" device this is a finding.'
  desc 'fix', 'Create if needed and set the contents of /etc/securetty to a "console" or "tty" device.
# echo console > /etc/securetty
or 
# echo tty1 > /etc/securetty'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36063r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4298'
  tag rid: 'SV-37376r1_rule'
  tag stig_id: 'GEN001000'
  tag gtitle: 'GEN001000'
  tag fix_id: 'F-31307r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000070']
  tag nist: ['AC-17 (4) (a)']
end
