control 'SV-226868' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29030r484888_chk'
  tag severity: 'medium'
  tag gid: 'V-226868'
  tag rid: 'SV-226868r603265_rule'
  tag stig_id: 'GEN003420'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29018r484889_fix'
  tag 'documentable'
  tag legacy: ['V-4365', 'SV-39886']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
