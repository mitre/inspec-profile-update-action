control 'SV-39828' do
  title 'Global initialization files must contain the mesg -n or mesg n commands.'
  desc 'If the mesg -n or mesg n command is not placed into the system profile, messaging can be used to cause a Denial of Service attack.'
  desc 'fix', 'Edit /etc/profile or another global initialization script and add the mesg -n command.'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-825'
  tag rid: 'SV-39828r1_rule'
  tag stig_id: 'GEN001780'
  tag gtitle: 'GEN001780'
  tag fix_id: 'F-979r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
