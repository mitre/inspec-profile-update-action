control 'SV-239169' do
  title 'The Photon operating system must be configured so that all global initialization scripts are protected from unauthorized modification.'
  desc "Local initialization files are used to configure the user's shell environment upon login. Malicious modification of these files could compromise accounts upon login."
  desc 'check', "At the command line, execute the following command:

# find /etc/bash.bashrc /etc/profile /etc/profile.d/ -xdev -type f -a '(' -perm -002 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command line, execute the following commands for each returned file:

# chmod o-w <file>
# chown root:root <file>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42380r675313_chk'
  tag severity: 'medium'
  tag gid: 'V-239169'
  tag rid: 'SV-239169r675315_rule'
  tag stig_id: 'PHTN-67-000098'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42339r675314_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
