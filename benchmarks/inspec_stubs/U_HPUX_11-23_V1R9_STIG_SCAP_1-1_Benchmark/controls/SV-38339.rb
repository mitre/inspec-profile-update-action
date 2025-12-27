control 'SV-38339' do
  title 'The /etc/group file must have mode 0444 or less permissive.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'fix', 'Change the mode of the /etc/group file to 0444 or less permissive.
# chmod 0444 /etc/group'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22337'
  tag rid: 'SV-38339r1_rule'
  tag stig_id: 'GEN001393'
  tag gtitle: 'GEN001393'
  tag fix_id: 'F-31653r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
