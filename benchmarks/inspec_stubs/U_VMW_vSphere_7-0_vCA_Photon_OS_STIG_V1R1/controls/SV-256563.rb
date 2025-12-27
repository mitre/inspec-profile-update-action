control 'SV-256563' do
  title 'The Photon operating system must be configured so that all files have a valid owner and group owner.'
  desc 'If files do not have valid user and group owners, unintended access to files could occur.'
  desc 'check', 'At the command line, run the following command:

# find / -fstype ext4 -nouser -o -nogroup -exec ls -ld {} \\; 2>/dev/null

If any files are returned, this is a finding.'
  desc 'fix', 'At the command line, run the following command for each returned file:

# chown root:root <file>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60238r887361_chk'
  tag severity: 'medium'
  tag gid: 'V-256563'
  tag rid: 'SV-256563r887363_rule'
  tag stig_id: 'PHTN-30-000094'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60181r887362_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
