control 'SV-38682' do
  title 'The /etc/securetty file must be owned by root.'
  desc 'Failure to make root the owner of sensitive files and utilities may provide unauthorized owners the potential to access and/or change sensitive information or system configurations, thus weakening the overall security posture of a site.'
  desc 'fix', 'Change the owner of the /etc/securetty file to root.
# chown root /etc/securetty'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-966'
  tag rid: 'SV-38682r1_rule'
  tag stig_id: 'GEN000000-HPUX0060'
  tag gtitle: 'GEN000000-HPUX0060'
  tag fix_id: 'F-1120r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
