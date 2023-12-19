control 'SV-226863' do
  title 'The at.allow file must have mode 0600 or less permissive.'
  desc 'Permissions more permissive than 0600 (read and write for the owner) may allow unauthorized or malicious access to the at.allow and/or at.deny files.'
  desc 'check', 'Check the mode of the at.allow file.
# ls -lL /etc/cron.d/at.allow
If the at.allow file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the at.allow file.
# chmod 0600 /etc/cron.d/at.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29025r484873_chk'
  tag severity: 'medium'
  tag gid: 'V-226863'
  tag rid: 'SV-226863r603265_rule'
  tag stig_id: 'GEN003340'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29013r484874_fix'
  tag 'documentable'
  tag legacy: ['V-987', 'SV-27388']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
