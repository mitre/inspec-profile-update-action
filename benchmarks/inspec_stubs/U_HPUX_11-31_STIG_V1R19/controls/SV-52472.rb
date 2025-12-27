control 'SV-52472' do
  title 'The per user PAM configuration file (/etc/pam_user.conf) must not be used to override the system-wide PAM configuration file (/etc/pam.conf) unless it is required.'
  desc 'The per user PAM configuration file (/etc/pam_user.conf) allows individual users to be assigned options that differ from those of the general computing community. This file is optional and should only be used if PAM applications are required to operate differently for specific users, i.e., to isolate the administrative user accounts.'
  desc 'check', 'If the system is configured for Trusted Mode, this check is not applicable.

For SMSE:
Check the system for the existence of the /etc/pam_user.conf file.
# ls -lL /etc/pam_user.conf

If the file does not exist, this is a finding.

If the file exists, examine the file.
# cat /etc/pam_user.conf

Attempt to determine the reason (ask the SA for an explanation) for options being passed to the PAM service modules for the listed users.

If the SA cannot provide an explanation for the listed users and PAM module options, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
If the SA cannot provide a reasonable explanation for user entries in the /etc/pam_user.conf file, take one or more of the following actions: remove the file, remove/comment all user entries, remove/comment individual user entries. Document all changes.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47023r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40483'
  tag rid: 'SV-52472r1_rule'
  tag stig_id: 'GEN000000-HPUX0400'
  tag gtitle: 'GEN000000-HPUX0400'
  tag fix_id: 'F-45432r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
