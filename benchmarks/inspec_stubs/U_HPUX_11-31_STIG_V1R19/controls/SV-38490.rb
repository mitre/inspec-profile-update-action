control 'SV-38490' do
  title 'All interactive user home directories must be owned by their respective users.'
  desc 'If users do not own their home directories, unauthorized users could access user files.'
  desc 'check', 'Check the ownership of each user home directory listed in the /etc/passwd file.

Procedure:
# ls -lLd <user home directory>

OR

# ls -lLd `cat /etc/passwd | cut -f 6,6 -d ":"` | more

If any user home directory is not owned by the assigned user, this is a finding.'
  desc 'fix', "Change the owner of a user's home directory to its assigned user.

Procedure:
# chown <user> <home directory>"
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36336r1_chk'
  tag severity: 'medium'
  tag gid: 'V-902'
  tag rid: 'SV-38490r1_rule'
  tag stig_id: 'GEN001500'
  tag gtitle: 'GEN001500'
  tag fix_id: 'F-31591r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
