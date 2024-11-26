control 'SV-227640' do
  title 'The /etc/passwd file must be owned by root.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Verify the /etc/passwd file is owned by root.

Procedure:
# ls -l /etc/passwd
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/passwd file to root.

# chown root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29802r488480_chk'
  tag severity: 'medium'
  tag gid: 'V-227640'
  tag rid: 'SV-227640r603266_rule'
  tag stig_id: 'GEN001378'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29790r488481_fix'
  tag 'documentable'
  tag legacy: ['V-22332', 'SV-26425']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
