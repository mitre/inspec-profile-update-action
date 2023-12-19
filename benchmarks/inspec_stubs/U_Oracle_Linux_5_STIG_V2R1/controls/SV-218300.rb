control 'SV-218300' do
  title 'The /etc/shadow (or equivalent) file must be owned by root.'
  desc "The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of the /etc/shadow file.

# ls -lL /etc/shadow

If the /etc/shadow file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the /etc/shadow (or equivalent) file.

# chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19775r568822_chk'
  tag severity: 'medium'
  tag gid: 'V-218300'
  tag rid: 'SV-218300r603259_rule'
  tag stig_id: 'GEN001400'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19773r568823_fix'
  tag 'documentable'
  tag legacy: ['V-797', 'SV-64569']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
