control 'SV-37979' do
  title 'The system must use available memory address randomization techniques.'
  desc 'Successful exploitation of buffer overflow vulnerabilities relies in some measure to having a predictable address structure of the executing program. Address randomization techniques reduce the probability of a successful exploit.'
  desc 'check', 'Verify exec-shield is enabled if present.
# cat /proc/sys/kernel/exec-shield
If the file is present and contains a value of "0", this is a finding.'
  desc 'fix', 'Edit the kernel boot parameters, or "/etc/sysctl.conf", and set exec-shield to "1". Reboot the system.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37277r1_chk'
  tag severity: 'low'
  tag gid: 'V-22576'
  tag rid: 'SV-37979r1_rule'
  tag stig_id: 'GEN008420'
  tag gtitle: 'GEN008420'
  tag fix_id: 'F-32513r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
