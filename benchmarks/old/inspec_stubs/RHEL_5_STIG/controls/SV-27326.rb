control 'SV-27326' do
  title 'The cron.allow file must have mode 0600 or less permissive.'
  desc 'A readable and/or writable cron.allow file by users other than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'fix', 'Change the mode of the cron.allow file to 0600.

Procedure:
# chmod 0600 /etc/cron.allow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-975'
  tag rid: 'SV-27326r1_rule'
  tag stig_id: 'GEN002980'
  tag gtitle: 'GEN002980'
  tag fix_id: 'F-24566r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
