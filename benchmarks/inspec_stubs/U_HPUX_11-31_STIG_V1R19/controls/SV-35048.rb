control 'SV-35048' do
  title 'A separate file system must be used for user home directories (such as /home or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from the / file system becoming full or failing.'
  desc 'check', %q(Determine if the /home path is a separate filesystem.
# cat /etc/fstab | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | \ grep -v "^#" | cut -f 2,2 -d " " | grep "^/home" | grep -v "/home/"

If the above command returns nothing, /home is not on a separate filesystem and this is a finding.)
  desc 'fix', 'Migrate the /home (or equivalent) path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36514r1_chk'
  tag severity: 'low'
  tag gid: 'V-12003'
  tag rid: 'SV-35048r1_rule'
  tag stig_id: 'GEN003620'
  tag gtitle: 'GEN003620'
  tag fix_id: 'F-31874r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001208']
  tag nist: ['SC-32']
end
