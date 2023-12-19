control 'SV-4088' do
  title 'User start-up files must not contain the mesg -y  or mesg y command.'
  desc 'The mesg -y or mesg y command turns on terminal messaging.  On systems that do not default to mesg -n, the system profile (or equivalent) provides it.  If the user changes this setting, write access may be provided to the terminal screen which could disrupt processing or cause enough confusion to result in damage to sensitive files.  Educate users about the danger of having terminal messaging set on.'
  desc 'check', '# grep "mesg" /<usershomedirectory>/.*                   

If local initialization files contain the mesg -y or mesg y command,  this is a finding.'
  desc 'fix', 'Edit the local initialization file(s) and remove the mesg -y command.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8218r2_chk'
  tag severity: 'low'
  tag gid: 'V-4088'
  tag rid: 'SV-4088r2_rule'
  tag stig_id: 'GEN001960'
  tag gtitle: 'GEN001960'
  tag fix_id: 'F-4021r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
