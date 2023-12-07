control 'SV-37390' do
  title 'The /etc/shells (or equivalent) file must exist.'
  desc 'The shells file (or equivalent) lists approved default shells. It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized unsecure shell.'
  desc 'fix', 'Create a /etc/shells file containing a list of valid system shells. Consult vendor documentation for an appropriate list of system shells.

Procedure:
# echo "/bin/bash" >> /etc/shells
# echo "/bin/csh" >> /etc/shells
(Repeat as necessary for other shells.)'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-916'
  tag rid: 'SV-37390r1_rule'
  tag stig_id: 'GEN002120'
  tag gtitle: 'GEN002120'
  tag fix_id: 'F-31321r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
