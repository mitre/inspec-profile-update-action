control 'SV-226870' do
  title '"At" jobs must not set the umask to a value less restrictive than 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask is often represented as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Determine what "at" jobs exist on the system.
Procedure:
# ls /var/spool/cron/atjobs

If there are no "at" jobs present, this is not applicable.

Determine if any of the "at" jobs or any scripts referenced execute the umask command. Check for any umask setting more permissive than 077.

# grep umask <at job or referenced script>

If any "at" job or referenced script sets umask to a value more permissive than 077, this is a finding.'
  desc 'fix', 'Edit "at" jobs or referenced scripts to remove umask commands setting umask to a value less restrictive than 077.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29032r484894_chk'
  tag severity: 'medium'
  tag gid: 'V-226870'
  tag rid: 'SV-226870r854428_rule'
  tag stig_id: 'GEN003440'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29020r484895_fix'
  tag 'documentable'
  tag legacy: ['V-4366', 'SV-40416']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
