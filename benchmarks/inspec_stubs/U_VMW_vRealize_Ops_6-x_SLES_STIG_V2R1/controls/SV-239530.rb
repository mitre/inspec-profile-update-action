control 'SV-239530' do
  title 'Files executed through a mail aliases file must be owned by root and must reside within a directory owned and writable only by root.'
  desc 'If a file executed through a mail aliases file is not owned and writable only by root, it may be subject to unauthorized modification. Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Verify the ownership of files referenced within the sendmail aliases file:

# more /etc/aliases

Examine the aliases file for any utilized directories or paths:

# ls -lL <directory or file path>

Check the owner for any paths referenced. Check if the file or parent directory is owned by root. 

If the file or parent directory is not owned by "root", this is a finding.'
  desc 'fix', 'Edit the "/etc/aliases" file (alternatively, /usr/lib/sendmail.cf). Locate the entries executing a program. They will appear similar to the following line:

Aliasname: : /usr/local/bin/ls (or some other program name)

Ensure "root" owns the programs and the directory(ies) they reside in by using the chown command to change owner to "root":

# chown root <file or directory name>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42763r662039_chk'
  tag severity: 'medium'
  tag gid: 'V-239530'
  tag rid: 'SV-239530r662041_rule'
  tag stig_id: 'VROM-SL-000555'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42722r662040_fix'
  tag 'documentable'
  tag legacy: ['SV-99181', 'V-88531']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
