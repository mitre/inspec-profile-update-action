control 'SV-227773' do
  title 'The "at"  directory must be owned by root, bin, or sys.'
  desc 'If the owner of the "at" directory is not root, bin, or sys, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the ownership of the "at" directory.

Procedure:
# ls -ld /var/spool/cron/atjobs 

If the directory is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the owner of the "at" directory to root, bin, or sys.

Procedure:
# chown root /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29935r489673_chk'
  tag severity: 'medium'
  tag gid: 'V-227773'
  tag rid: 'SV-227773r603266_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29923r489674_fix'
  tag 'documentable'
  tag legacy: ['V-4365', 'SV-39886']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
