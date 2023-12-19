control 'SV-37461' do
  title 'The hosts.lpd (or equivalent) must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'fix', 'Change the mode of the /etc/cups/printers.conf file to 0664 or less permissive.

Procedure:
# chmod 0664 /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-829'
  tag rid: 'SV-37461r1_rule'
  tag stig_id: 'GEN003940'
  tag gtitle: 'GEN003940'
  tag fix_id: 'F-31371r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
