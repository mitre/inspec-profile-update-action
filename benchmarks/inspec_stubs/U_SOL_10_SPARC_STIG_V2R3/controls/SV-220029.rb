control 'SV-220029' do
  title "All interactive user's home directories must be owned by their respective users."
  desc 'If users do not own their home directories, unauthorized users could access user files.'
  desc 'check', "Check the ownership of each user's home directory listed in the /etc/passwd file.
 
Procedure:  
# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld | more

If any user's home directory is not owned by the assigned user, this is a finding."
  desc 'fix', "Change the owner of a user's home directory to its assigned user.

Procedure:
# chown <user> <home directory>"
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21738r482984_chk'
  tag severity: 'medium'
  tag gid: 'V-220029'
  tag rid: 'SV-220029r603265_rule'
  tag stig_id: 'GEN001500'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21737r482985_fix'
  tag 'documentable'
  tag legacy: ['SV-39822', 'V-902']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
