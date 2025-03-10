control 'SV-215260' do
  title 'AIX must remove NOPASSWD tag from sudo config files.'
  desc 'sudo command does not require reauthentication if NOPASSWD tag is specified in /etc/sudoers config file, or sudoers files in /etc/sudoers.d/ directory. With this tag in sudoers file, users are not required to reauthenticate for privilege escalation.'
  desc 'check', 'If sudo is not used on AIX, this is Not Applicable.

Run the following command to find the "NOPASSWD" tag in "/etc/sudoers" file:
# grep NOPASSWD /etc/sudoers

If there is a "NOPASSWD" tag found in "/etc/sudoers" file, this is a finding.

Run the following command to find the "NOPASSWD" tag in one of the sudo config files in "/etc/sudoers.d/" directory:
# find /etc/sudoers.d -type f -exec grep -l NOPASSWD {} \\;

The above command displays all sudo config files that are in "/etc/sudoers.d/" directory and they contain the "NOPASSWD" tag.

If above command found a config file that is in "/etc/sudoers.d/" directory and contains the "NOPASSWD" tag, this is a finding.'
  desc 'fix', 'Edit  "/etc/sudoers" using "visudo" command to remove all the "NOPASSWD" tags:
# visudo -f 

Editing a sudo config file that is in "/etc/sudoers.d/" directory and contains the "NOPASSWD" tags, use "visudo" the command as follows:
# visudo -f /etc/sudoers.d/<config_file_name>'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16458r294231_chk'
  tag severity: 'high'
  tag gid: 'V-215260'
  tag rid: 'SV-215260r853468_rule'
  tag stig_id: 'AIX7-00-002061'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-16456r294232_fix'
  tag 'documentable'
  tag legacy: ['SV-101635', 'V-91537']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
