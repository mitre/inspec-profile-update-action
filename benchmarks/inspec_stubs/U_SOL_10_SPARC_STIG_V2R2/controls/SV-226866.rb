control 'SV-226866' do
  title 'The "at" directory must have mode 0755 or less permissive.'
  desc 'If the "at" directory has a mode more permissive than 0755, unauthorized users could be allowed to view or to edit files containing sensitive information within the "at" directory.  Unauthorized modifications could result in Denial of Service to authorized "at" jobs.'
  desc 'check', 'Check the mode of the "at" directory.

Procedure:
# ls -ld /var/spool/cron/atjobs

If the directory mode is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the "at" directory to 0755.

Procedure:
# chmod 0755 < at directory >'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29028r484882_chk'
  tag severity: 'medium'
  tag gid: 'V-226866'
  tag rid: 'SV-226866r603265_rule'
  tag stig_id: 'GEN003400'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29016r484883_fix'
  tag 'documentable'
  tag legacy: ['V-4364', 'SV-40391']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
