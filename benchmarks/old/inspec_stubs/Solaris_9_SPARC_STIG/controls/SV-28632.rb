control 'SV-28632' do
  title 'The system must use a separate filesystem for /tmp (or equivalent).'
  desc 'The use of separate filesystems for different paths can protect the system from failures resulting from a filesystem becoming full or failing.'
  desc 'fix', 'Migrate the /tmp path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-23739'
  tag rid: 'SV-28632r1_rule'
  tag stig_id: 'GEN003624'
  tag gtitle: 'GEN003624'
  tag fix_id: 'F-25907r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
