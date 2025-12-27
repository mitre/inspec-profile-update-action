control 'SV-38399' do
  title 'The system must use available memory address randomization techniques.'
  desc 'Successful exploitation of buffer overflow vulnerabilities relies in some measure to having a predictable address structure of the executing program. Address randomization techniques reduce the probability of a successful exploit.'
  desc 'check', 'This check is not applicable (NA) for HPUX.'
  desc 'fix', 'This check/fix is not applicable (NA) for HPUX.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36787r1_chk'
  tag severity: 'low'
  tag gid: 'V-22576'
  tag rid: 'SV-38399r1_rule'
  tag stig_id: 'GEN008420'
  tag gtitle: 'GEN008420'
  tag fix_id: 'F-32166r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
