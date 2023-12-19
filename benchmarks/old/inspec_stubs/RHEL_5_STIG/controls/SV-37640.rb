control 'SV-37640' do
  title 'A separate file system must be used for user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'fix', 'Migrate the /home (or equivalent) path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-12003'
  tag rid: 'SV-37640r1_rule'
  tag stig_id: 'GEN003620'
  tag gtitle: 'GEN003620'
  tag fix_id: 'F-31675r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
