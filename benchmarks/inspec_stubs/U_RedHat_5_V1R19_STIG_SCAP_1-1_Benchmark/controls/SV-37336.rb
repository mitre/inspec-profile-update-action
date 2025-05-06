control 'SV-37336' do
  title 'The /etc/passwd file must be owned by root.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'fix', 'Change the owner of the /etc/passwd file to root.
# chown root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22332'
  tag rid: 'SV-37336r1_rule'
  tag stig_id: 'GEN001378'
  tag gtitle: 'GEN001378'
  tag fix_id: 'F-31273r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
