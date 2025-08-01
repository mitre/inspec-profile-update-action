control 'SV-37163' do
  title 'All interactive user home directories must be owned by their respective users.'
  desc 'If users do not own their home directories, unauthorized users could access user files.'
  desc 'check', 'Check the ownership of each user home directory listed in the /etc/passwd file.

Procedure:
# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld 

If any user home directory is not owned by the assigned user, this is a finding.'
  desc 'fix', "Change the owner of a user's home directory to its assigned user.

Procedure:
# chown <user> <home directory>"
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37526r1_chk'
  tag severity: 'medium'
  tag gid: 'V-902'
  tag rid: 'SV-37163r1_rule'
  tag stig_id: 'GEN001500'
  tag gtitle: 'GEN001500'
  tag fix_id: 'F-1056r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
