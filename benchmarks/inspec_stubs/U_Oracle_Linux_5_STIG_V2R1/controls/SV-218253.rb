control 'SV-218253' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19728r568693_chk'
  tag severity: 'medium'
  tag gid: 'V-218253'
  tag rid: 'SV-218253r603259_rule'
  tag stig_id: 'GEN001000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19726r568694_fix'
  tag 'documentable'
  tag legacy: ['V-4298', 'SV-64393']
  tag cci: ['CCI-000366', 'CCI-000070']
  tag nist: ['CM-6 b', 'AC-17 (4) (a)']
end
