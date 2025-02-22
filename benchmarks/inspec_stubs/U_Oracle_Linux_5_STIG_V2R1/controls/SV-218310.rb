control 'SV-218310' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19785r554267_chk'
  tag severity: 'medium'
  tag gid: 'V-218310'
  tag rid: 'SV-218310r603259_rule'
  tag stig_id: 'GEN001500'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19783r554268_fix'
  tag 'documentable'
  tag legacy: ['V-902', 'SV-64589']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
