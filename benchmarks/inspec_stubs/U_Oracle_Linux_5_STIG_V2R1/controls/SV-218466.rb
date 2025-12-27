control 'SV-218466' do
  title 'At jobs must not set the umask to a value less restrictive than 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  A umask of 077 limits new files to mode 700 or less permissive.  Although umask is often represented as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.'
  desc 'check', 'Determine what "at" jobs exist on the system.
Procedure:
# ls /var/spool/at

If there are no "at" jobs present, this is not applicable.

Determine if any of the "at" jobs or any scripts referenced execute the "umask" command. Check for any umask setting more permissive than 077.

# grep umask <at job or referenced script>

If any "at" job or referenced script sets umask to a value more permissive than 077, this is a finding.'
  desc 'fix', 'Edit "at" jobs or referenced scripts to remove "umask" commands that set umask to a value less restrictive than 077.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19941r569131_chk'
  tag severity: 'medium'
  tag gid: 'V-218466'
  tag rid: 'SV-218466r603259_rule'
  tag stig_id: 'GEN003440'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19939r569132_fix'
  tag 'documentable'
  tag legacy: ['V-4366', 'SV-64409']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
