control 'SV-38941' do
  title "The root account's home directory (other than /) must have mode 0700."
  desc 'Permissions greater than 0700 could allow unauthorized users access to the root home directory.'
  desc 'check', %q(Check the mode of the root home directory.

Procedure:
# grep "^root" /etc/passwd | awk -F":" '{print $6}'
# ls -ld <root home directory>

If the mode of the directory is not equal to 0700, this is a finding. If the home directory is /, this is not applicable.)
  desc 'fix', 'The root home directory will have permissions of 0700. Do not change the protections of the / directory. Use the following command to change protections for the root home directory.
# chmod 0700 /root.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28063r1_chk'
  tag severity: 'medium'
  tag gid: 'V-775'
  tag rid: 'SV-38941r1_rule'
  tag stig_id: 'GEN000920'
  tag gtitle: 'GEN000920'
  tag fix_id: 'F-32119r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
