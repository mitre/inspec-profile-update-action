control 'SV-39505' do
  title 'The system must use a separate file system for /tmp (or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /tmp path is a separate file system.

# df -k /tmp

If /tmp is not its own file system, this is a finding.'
  desc 'fix', 'Migrate the /tmp path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37874r1_chk'
  tag severity: 'low'
  tag gid: 'V-23739'
  tag rid: 'SV-39505r1_rule'
  tag stig_id: 'GEN003624'
  tag gtitle: 'GEN003624'
  tag fix_id: 'F-33126r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
