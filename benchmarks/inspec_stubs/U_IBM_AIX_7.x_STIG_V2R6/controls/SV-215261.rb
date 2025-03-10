control 'SV-215261' do
  title 'AIX must remove !authenticate option from sudo config files.'
  desc 'sudo command does not require reauthentication if !authenticate option is specified in /etc/sudoers config file, or config files in /etc/sudoers.d/ directory. With this tag in sudoers, users are not required to reauthenticate for privilege escalation.'
  desc 'check', 'If sudo is not used on AIX, this is Not Applicable.

Run the following command to find "!authenticate" option in "/etc/sudoers" file:
# grep "!authenticate" /etc/sudoers

If there is a "!authenticate" option found in "/etc/sudoers" file, this is a finding.

Run the following command to find "!authenticate" option in one of the sudo config files in "/etc/sudoers.d/" directory:
# find /etc/sudoers.d -type f -exec grep -l "!authenticate" {} \\;

The above command displays all sudo config files that are in "/etc/sudoers.d/" directory and they contain the "!authenticate" option.

If above command found a config file that is in "/etc/sudoers.d/" directory and that contains the "!authenticate" option, this is a finding.'
  desc 'fix', 'Edit "/etc/sudoers" using "visudo" command to remove all the "!authenticate" options:
# visudo -f /etc/sudoers

Editing a sudo config file that is in "/etc/sudoers.d/" directory and contains "!authenticate" options, use the "visudo" command as follows:
# visudo -f /etc/sudoers.d/<config_file_name>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16459r294234_chk'
  tag severity: 'medium'
  tag gid: 'V-215261'
  tag rid: 'SV-215261r508663_rule'
  tag stig_id: 'AIX7-00-002062'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-16457r294235_fix'
  tag 'documentable'
  tag legacy: ['SV-101637', 'V-91539']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
