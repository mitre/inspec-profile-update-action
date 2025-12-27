control 'SV-218173' do
  title 'The /etc/security/access.conf file must have mode 0640 or less permissive.'
  desc 'If the access permissions are more permissive than 0640, system security could be compromised.'
  desc 'check', 'Check access configuration mode:

# ls -lL /etc/security/access.conf

If this file exists and has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Use the chmod command to set the permissions to 0640.
(for example:
# chmod 0640 /etc/security/access.conf

).'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19648r553856_chk'
  tag severity: 'medium'
  tag gid: 'V-218173'
  tag rid: 'SV-218173r603259_rule'
  tag stig_id: 'GEN000000-LNX00440'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19646r553857_fix'
  tag 'documentable'
  tag legacy: ['V-1055', 'SV-62903']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
