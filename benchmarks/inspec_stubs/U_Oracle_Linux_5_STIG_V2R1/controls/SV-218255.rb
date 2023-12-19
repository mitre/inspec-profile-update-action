control 'SV-218255' do
  title 'The sudo command must require authentication.'
  desc 'The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root.  The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run.  Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.'
  desc 'check', %q(Verify neither the "NOPASSWD" option nor the "!authenticate" option is configured for use in "/etc/sudoers" and associated files. Note that the "#include" and "#includedir" directives may be used to include configuration data from locations other than the defaults enumerated here.

# egrep '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*
# egrep '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*

If the "NOPASSWD" or "!authenticate" options are configured for use in "/etc/sudoers" or associated files, this is a finding.)
  desc 'fix', 'Update the "/etc/sudoers" or other sudo configuration files to remove or comment out lines utilizing the "NOPASSWD" and "!authenticate" options.

# visudo
# visudo -f [other sudo configuration file]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19730r568699_chk'
  tag severity: 'medium'
  tag gid: 'V-218255'
  tag rid: 'SV-218255r603259_rule'
  tag stig_id: 'GEN001025'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-19728r568700_fix'
  tag 'documentable'
  tag legacy: ['V-58539', 'SV-75261']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
