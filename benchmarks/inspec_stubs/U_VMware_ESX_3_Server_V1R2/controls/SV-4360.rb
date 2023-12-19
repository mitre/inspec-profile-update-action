control 'SV-4360' do
  title 'Cron programs must not set the umask to a value less restrictive than 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  A umask of 077 limits new files to a mode of 700 or less permissive.  Although umask is often represented as a 4-digit octal number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Check programs run from cron for umask settings.  If any specify a umask more permissive than 077, this is a finding.'
  desc 'fix', 'Edit cron script files and modify the umask to 077.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8222r2_chk'
  tag severity: 'low'
  tag gid: 'V-4360'
  tag rid: 'SV-4360r2_rule'
  tag stig_id: 'GEN003220'
  tag gtitle: 'GEN003220'
  tag fix_id: 'F-4271r2_fix'
  tag severity_override_guidance: 'If a cron program sets the umask to 000 or does not restrict the world-writable permission, this becomes a CAT I finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
