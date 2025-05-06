control 'SV-208913' do
  title 'The telnet-server package must not be installed.'
  desc %q(Removing the "telnet-server" package decreases the risk of the unencrypted telnet service's accidental (or intentional) activation.

Mitigation:  If the telnet-server package is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.)
  desc 'check', 'Run the following command to determine if the "telnet-server" package is installed: 

# rpm -q telnet-server

If the package is installed, this is a finding.'
  desc 'fix', 'The "telnet-server" package can be uninstalled with the following command: 

# yum erase telnet-server'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9166r357719_chk'
  tag severity: 'high'
  tag gid: 'V-208913'
  tag rid: 'SV-208913r603263_rule'
  tag stig_id: 'OL6-00-000206'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-9166r357720_fix'
  tag 'documentable'
  tag legacy: ['V-50551', 'SV-64757']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
