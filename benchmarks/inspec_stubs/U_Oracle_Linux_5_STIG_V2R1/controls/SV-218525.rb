control 'SV-218525' do
  title 'The hosts.lpd (or equivalent) file must not have an extended ACL.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', "Check the permissions of the /etc/cups/printers.conf file.

# ls -lL /etc/cups/printers.conf

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20000r562696_chk'
  tag severity: 'medium'
  tag gid: 'V-218525'
  tag rid: 'SV-218525r603259_rule'
  tag stig_id: 'GEN003950'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19998r562697_fix'
  tag 'documentable'
  tag legacy: ['V-22436', 'SV-63475']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
