control 'SV-37533' do
  title 'The at.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.allow file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'fix', 'Change the owner of the at.allow file.
# chown root /etc/at.allow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4367'
  tag rid: 'SV-37533r1_rule'
  tag stig_id: 'GEN003460'
  tag gtitle: 'GEN003460'
  tag fix_id: 'F-31448r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
