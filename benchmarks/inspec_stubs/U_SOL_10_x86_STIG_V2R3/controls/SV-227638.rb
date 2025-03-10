control 'SV-227638' do
  title 'The /etc/nsswitch.conf file must have mode 0644 or less permissive.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Check the mode of the /etc/nsswitch.conf file.

Procedure:
# ls -l /etc/nsswitch.conf
If the file mode is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/nsswitch.conf file to 0644 or less permissive.

Procedure:
# chmod 0644 /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29800r488474_chk'
  tag severity: 'medium'
  tag gid: 'V-227638'
  tag rid: 'SV-227638r603266_rule'
  tag stig_id: 'GEN001373'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29788r488475_fix'
  tag 'documentable'
  tag legacy: ['V-22329', 'SV-26419']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
