control 'SV-35112' do
  title 'Samba must be configured to not allow guest access to shares.'
  desc 'Guest access to shares permits anonymous access and is not permitted.'
  desc 'check', %q(Check the guest setting the Samba configuration.
# cat /etc/opt/samba/smb.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i "^guest ok = yes"

If the setting exists and is set to yes, this is a finding.)
  desc 'fix', 'Edit the /etc/opt/samba/smb.conf file and change the guest ok setting to no, for example:

      guest ok = no'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22501'
  tag rid: 'SV-35112r1_rule'
  tag stig_id: 'GEN006235'
  tag gtitle: 'GEN006235'
  tag fix_id: 'F-32084r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
