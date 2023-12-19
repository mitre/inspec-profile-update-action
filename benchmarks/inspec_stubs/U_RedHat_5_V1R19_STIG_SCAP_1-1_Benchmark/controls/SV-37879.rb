control 'SV-37879' do
  title 'The /etc/smbpasswd file must be owned by root.'
  desc 'If the "smbpasswd" file is not owned by root, it may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'fix', 'Use the chown command to configure the files maintained by smbpasswd.
For instance:
# chown root /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1029'
  tag rid: 'SV-37879r1_rule'
  tag stig_id: 'GEN006160'
  tag gtitle: 'GEN006160'
  tag fix_id: 'F-32373r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
