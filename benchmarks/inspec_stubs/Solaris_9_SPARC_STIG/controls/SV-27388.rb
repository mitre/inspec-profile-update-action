control 'SV-27388' do
  title 'The at.allow file must have mode 0600 or less permissive.'
  desc 'Permissions more permissive than 0600 (read and write for the owner) may allow unauthorized or malicious access to the at.allow and/or at.deny files.'
  desc 'fix', 'Change the mode of the at.allow file.
# chmod 0600 /etc/cron.d/at.allow'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-987'
  tag rid: 'SV-27388r1_rule'
  tag stig_id: 'GEN003340'
  tag gtitle: 'GEN003340'
  tag fix_id: 'F-24632r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
