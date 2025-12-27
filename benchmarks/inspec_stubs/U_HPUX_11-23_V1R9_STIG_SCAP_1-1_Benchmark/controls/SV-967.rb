control 'SV-967' do
  title 'The /etc/securetty file must have mode 0640 or less permissive.'
  desc "Excessive permissions on the /etc/securetty file could result in unauthorized modification of the file.  Changes to the file could reduce the system's security by specifying additional terminals permitted to accept root logins, or deny service by preventing root logins on authorized terminals."
  desc 'fix', 'Change the mode of the /etc/securetty file to 0640.

Example:
# chmod 0640 /etc/securetty'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-967'
  tag rid: 'SV-967r2_rule'
  tag stig_id: 'GEN000000-HPUX0100'
  tag gtitle: 'GEN000000-HPUX0100'
  tag fix_id: 'F-1121r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECLP-1, ECCD-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
