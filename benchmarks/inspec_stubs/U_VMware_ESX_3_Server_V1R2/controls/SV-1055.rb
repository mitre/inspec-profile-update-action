control 'SV-1055' do
  title 'The /etc/access.conf file must have mode 0640 or less permissive.'
  desc 'If the access permissions are more permissive than 0640, system security could be compromised.'
  desc 'check', 'Check access configuration mode:

# ls -lL /etc/login.access /etc/security/access.conf /etc/access.conf

If any of these files exist and have a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Use the chmod command to set the permissions to 0640.
For example:
# chmod 0640 /etc/login.access /etc/security/access.conf /etc/access.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2045r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1055'
  tag rid: 'SV-1055r2_rule'
  tag stig_id: 'GEN000000-LNX00440'
  tag gtitle: 'GEN000000-LNX00440'
  tag fix_id: 'F-1209r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
