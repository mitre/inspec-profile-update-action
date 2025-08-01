control 'SV-26425' do
  title 'The /etc/passwd file must be owned by root.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Verify the /etc/passwd file is owned by root.

Procedure:
# ls -l /etc/passwd
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/passwd file to root.

# chown root /etc/passwd'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27501r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22332'
  tag rid: 'SV-26425r1_rule'
  tag stig_id: 'GEN001378'
  tag gtitle: 'GEN001378'
  tag fix_id: 'F-23612r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
