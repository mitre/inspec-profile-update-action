control 'SV-226902' do
  title 'The system must use a separate filesystem for /tmp (or equivalent).'
  desc 'The use of separate filesystems for different paths can protect the system from failures resulting from a filesystem becoming full or failing.'
  desc 'check', 'Determine if the /tmp path is a separate file system.
# grep /tmp /etc/vfstab
If no result is returned, /tmp is not on a separate file system, this is a finding.
If the returned result indicates that /tmp is mounted on a memory or swap based file system, this is not a finding'
  desc 'fix', 'Migrate the /tmp path onto a separate file system.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29064r484993_chk'
  tag severity: 'low'
  tag gid: 'V-226902'
  tag rid: 'SV-226902r603265_rule'
  tag stig_id: 'GEN003624'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29052r484994_fix'
  tag 'documentable'
  tag legacy: ['V-23739', 'SV-28632']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
