control 'SV-218712' do
  title 'The system must use available memory address randomization techniques.'
  desc 'Successful exploitation of buffer overflow vulnerabilities relies in some measure to having a predictable address structure of the executing program. Address randomization techniques reduce the probability of a successful exploit.'
  desc 'check', %q(Check that the "kernel.randomize_va_space" kernel parameter is set to "2" in /etc/sysctl.conf.

Procedure:

# grep ^kernel\.randomize_va_space /etc/sysctl.conf | awk -F= '{ print $2 }'

If there is no value returned or if a value is returned that is not "2", this is a finding.)
  desc 'fix', 'Edit (or add if necessary) the entry in /etc/sysctl.conf for the "kernel.randomize_va_space" kernel parameter.  Ensure  this parameter is set to "2" as in:

kernel.randomize_va_space = 2

If this was not already the default, reboot the system for the change to take effect.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20187r556553_chk'
  tag severity: 'low'
  tag gid: 'V-218712'
  tag rid: 'SV-218712r603259_rule'
  tag stig_id: 'GEN008420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20185r556554_fix'
  tag 'documentable'
  tag legacy: ['V-22576', 'SV-63197']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
