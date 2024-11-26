control 'SV-226472' do
  title "The root account's home directory (other than /) must have mode 0700."
  desc 'Permissions greater than 0700 could allow unauthorized users access to the root home directory.'
  desc 'check', %q(Check the mode of the root home directory.

Procedure:
# grep "^root" /etc/passwd | awk -F":" '{print $6}'
# ls -ld <root home directory>

If the mode of the directory is not equal to 0700, this is a finding. If the home directory is /, this is not applicable.)
  desc 'fix', 'The root home directory will have permissions of 0700. Do not change the protections of the / directory. Use the following command to change protections for the root home directory.
# chmod 0700 /rootdir.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28633r482798_chk'
  tag severity: 'medium'
  tag gid: 'V-226472'
  tag rid: 'SV-226472r603265_rule'
  tag stig_id: 'GEN000920'
  tag gtitle: 'SRG-OS-000326'
  tag fix_id: 'F-28621r482799_fix'
  tag 'documentable'
  tag legacy: ['V-775', 'SV-775']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
