control 'SV-216202' do
  title 'The operating system must reveal error messages only to authorized personnel.'
  desc 'Proper file permissions and ownership ensures that only designated personnel in the organization can access error messages.'
  desc 'check', 'Check the permissions of the /var/adm/messages file:
# ls -l /var/adm/messages

Check the permissions of the /var/adm directory:
# ls -ld /var/adm

If the owner and group of /var/adm/messages is not root and the permissions are not 640, this is a finding.

If the owner of /var/adm is not root, group is not sys, and the permissions are not 750, this is a finding.'
  desc 'fix', 'The root role is required.

Change the permissions and owner on the /var/adm/messages file:

# chmod 640 /var/adm/messages
# chown root /var/adm/messages
# chgrp root /var/adm/messages

Change the permissions and owner on the /var/adm directory:

# chmod 750 /var/adm
# chown root /var/adm
# chgrp sys /var/adm'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17440r372988_chk'
  tag severity: 'low'
  tag gid: 'V-216202'
  tag rid: 'SV-216202r603268_rule'
  tag stig_id: 'SOL-11.1-070240'
  tag gtitle: 'SRG-OS-000206'
  tag fix_id: 'F-17438r372989_fix'
  tag 'documentable'
  tag legacy: ['V-48033', 'SV-60905']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
