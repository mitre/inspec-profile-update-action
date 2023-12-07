control 'SV-37642' do
  title 'The system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'fix', 'Migrate the /var/log/audit path onto a separate filesystem.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-23738'
  tag rid: 'SV-37642r1_rule'
  tag stig_id: 'GEN003623'
  tag gtitle: 'GEN003623'
  tag fix_id: 'F-31677r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
