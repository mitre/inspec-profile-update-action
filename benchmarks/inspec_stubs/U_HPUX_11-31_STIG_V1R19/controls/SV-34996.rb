control 'SV-34996' do
  title '"At" jobs must not set the umask to a value less restrictive than 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask is often represented as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Determine what at jobs exist on the system.
Procedure:

# ls /var/spool/cron/atjobs

If there are no at jobs present, this is not applicable.

Determine if any of the at jobs or any scripts referenced execute the umask command. Check for any umask setting more permissive than 077.

# grep -n umask <at job or referenced script>

If any at job or referenced script sets umask to a value more permissive than 077, this is a finding.

NOTE: The at facility will set the execution environment umask to 022. A grep of the at file will normally yield a line in the file that may look like umask 2. When examining any at job command file, this should not be mistaken for a user defined umask (re-)setting.'
  desc 'fix', 'Edit at jobs or referenced scripts to remove umask commands setting the umask value more permissive than 077.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4366'
  tag rid: 'SV-34996r1_rule'
  tag stig_id: 'GEN003440'
  tag gtitle: 'GEN003440'
  tag fix_id: 'F-30201r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
