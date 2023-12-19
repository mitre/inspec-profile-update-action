control 'SV-218289' do
  title 'The /etc/nsswitch.conf file must have mode 0644 or less permissive.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Check the mode of the /etc/nsswitch.conf file.

# ls -l /etc/nsswitch.conf

If the file mode is not 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/nsswitch.conf file to 0644 or less permissive.

# chmod 0644 /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19764r561656_chk'
  tag severity: 'medium'
  tag gid: 'V-218289'
  tag rid: 'SV-218289r603259_rule'
  tag stig_id: 'GEN001373'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19762r561657_fix'
  tag 'documentable'
  tag legacy: ['V-22329', 'SV-64541']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
