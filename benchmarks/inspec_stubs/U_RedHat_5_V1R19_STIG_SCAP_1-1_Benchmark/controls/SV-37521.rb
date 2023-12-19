control 'SV-37521' do
  title 'The "at" directory must have mode 0755 or less permissive.'
  desc 'If the "at" directory has a mode more permissive than 0755, unauthorized users could be allowed to view or to edit files containing sensitive information within the "at" directory.  Unauthorized modifications could result in Denial of Service to authorized "at" jobs.'
  desc 'fix', 'Change the mode of the "at" directory to 0755.

Procedure:
# chmod 0755 <at directory>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4364'
  tag rid: 'SV-37521r1_rule'
  tag stig_id: 'GEN003400'
  tag gtitle: 'GEN003400'
  tag fix_id: 'F-31433r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
