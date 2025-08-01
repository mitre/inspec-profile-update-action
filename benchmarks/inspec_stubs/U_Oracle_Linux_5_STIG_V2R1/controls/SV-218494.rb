control 'SV-218494' do
  title 'The system must use a separate file system for /tmp (or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the /tmp path is a separate filesystem.
# egrep "[\\t ]/tmp[\\t ]" /etc/fstab
If no result is returned, /tmp is not on a separate filesystem this is a finding.'
  desc 'fix', 'Migrate the /tmp path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19969r562618_chk'
  tag severity: 'low'
  tag gid: 'V-218494'
  tag rid: 'SV-218494r603259_rule'
  tag stig_id: 'GEN003624'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19967r562619_fix'
  tag 'documentable'
  tag legacy: ['V-23739', 'SV-64221']
  tag cci: ['CCI-000366', 'CCI-001208']
  tag nist: ['CM-6 b', 'SC-32']
end
