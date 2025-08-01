control 'SV-37558' do
  title 'Device files used for backup must only be readable and/or writable by root or the backup user.'
  desc 'System backups could be accidentally or maliciously overwritten and destroy the ability to recover the system if a compromise should occur.  Unauthorized users could also copy system files.'
  desc 'check', 'Check the system for world-writable device files.

Procedure:
# find / -perm -2 -a \\( -type b -o -type c \\) -exec ls -ld {} \\;

Ask the SA to identify any device files used for backup purposes.

If any device file(s) used for backup are writable by users other than root or the designated backup user, this is a finding.'
  desc 'fix', 'Use the chmod command to remove the world-writable bit from the backup device files. 

Procedure:
# chmod o-w <back device filename>

Document all changes.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36209r4_chk'
  tag severity: 'medium'
  tag gid: 'V-925'
  tag rid: 'SV-37558r1_rule'
  tag stig_id: 'GEN002300'
  tag gtitle: 'GEN002300'
  tag fix_id: 'F-31469r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
