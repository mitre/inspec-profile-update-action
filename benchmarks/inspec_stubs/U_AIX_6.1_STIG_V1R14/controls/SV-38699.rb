control 'SV-38699' do
  title 'The system must not allow directed broadcasts to gateway.'
  desc 'Disabling directed broadcast prevents packets directed to a gateway to be broadcasted on a remote network.'
  desc 'check', 'Check the directed_broadcast option.

# /usr/sbin/no -o directed_broadcast

If the value returned is not 0,  this is a finding.'
  desc 'fix', 'Configure directed_broadcast  to 0.

# /usr/sbin/no -p -o directed_broadcast=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29495'
  tag rid: 'SV-38699r1_rule'
  tag stig_id: 'GEN000000-AIX0200'
  tag gtitle: 'GEN000000-AIX0200'
  tag fix_id: 'F-33053r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
