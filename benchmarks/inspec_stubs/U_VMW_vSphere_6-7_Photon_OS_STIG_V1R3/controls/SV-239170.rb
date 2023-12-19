control 'SV-239170' do
  title 'The Photon operating system must be configured so that all system startup scripts are protected from unauthorized modification.'
  desc 'If system startup scripts are accessible to unauthorized modification, this could compromise the system on startup.'
  desc 'check', "At the command line, execute the following command:

# find /etc/rc.d/* -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command line, execute the following commands for each returned file:

# chmod o-w <file>
# chown root:root <file>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42381r675316_chk'
  tag severity: 'medium'
  tag gid: 'V-239170'
  tag rid: 'SV-239170r675318_rule'
  tag stig_id: 'PHTN-67-000099'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42340r675317_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
