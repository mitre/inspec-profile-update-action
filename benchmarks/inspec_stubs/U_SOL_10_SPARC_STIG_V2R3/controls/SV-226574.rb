control 'SV-226574' do
  title 'Device files used for backup must only be readable and/or writable by root or the backup user.'
  desc 'System backups could be accidentally or maliciously overwritten and destroy the ability to recover the system if a compromise should occur.  Unauthorized users could also copy system files.'
  desc 'check', 'Check the system for world-writable device files.

Procedure:
# find / -perm -2 -a \\( -type b -o -type c \\) -exec ls -ld {} \\;

If any device file(s) used for backup are writable by users other than root, this is a finding.'
  desc 'fix', 'Use the chmod command to remove the world-writable bit from the backup device files.  

Procedure:
# chmod o-w backdevicefilename

Document all changes.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28735r483131_chk'
  tag severity: 'medium'
  tag gid: 'V-226574'
  tag rid: 'SV-226574r603265_rule'
  tag stig_id: 'GEN002300'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28723r483132_fix'
  tag 'documentable'
  tag legacy: ['SV-925', 'V-925']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
