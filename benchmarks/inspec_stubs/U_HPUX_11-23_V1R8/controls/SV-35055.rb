control 'SV-35055' do
  title 'The system must use a separate file system for /tmp (or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', %q(Determine if the /tmp path is a separate filesystem.

# cat /etc/fstab | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | \ grep -v "^#" | cut -f 2,2 -d " " | grep "^/tmp"  | grep -v "/tmp/"

If the above command returns nothing, /tmp is not on a separate filesystem and this is a finding.)
  desc 'fix', 'Migrate the /tmp path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34925r1_chk'
  tag severity: 'low'
  tag gid: 'V-23739'
  tag rid: 'SV-35055r1_rule'
  tag stig_id: 'GEN003624'
  tag gtitle: 'GEN003624'
  tag fix_id: 'F-30230r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
