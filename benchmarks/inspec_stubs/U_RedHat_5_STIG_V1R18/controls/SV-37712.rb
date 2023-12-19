control 'SV-37712' do
  title 'The /etc/news/infeed.conf (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the "" file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'RHEL uses the InternetNewsDaemon (innd) news server. The file that corresponds to "/etc/news/hosts.nntp.nolimit" is "/etc/news/infeed.conf". Check the permissions for "/etc/news/infeed.conf".

# ls -lL /etc/news/infeed.conf

If "/etc/news/infeed.conf" has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of "/etc/news/infeed.conf" to 0600.
# chmod 0600 /etc/news/infeed.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4274'
  tag rid: 'SV-37712r1_rule'
  tag stig_id: 'GEN006280'
  tag gtitle: 'GEN006280'
  tag fix_id: 'F-32122r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
