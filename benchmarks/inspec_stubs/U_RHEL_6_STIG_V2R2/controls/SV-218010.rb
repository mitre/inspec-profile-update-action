control 'SV-218010' do
  title 'The openldap-servers package must not be installed unless required.'
  desc 'Unnecessary packages should not be installed to decrease the attack surface of the system.'
  desc 'check', 'To verify the "openldap-servers" package is not installed, run the following command: 

$ rpm -q openldap-servers

The output should show the following. 

package openldap-servers is not installed


If it does not, this is a finding.'
  desc 'fix', 'The "openldap-servers" package should be removed if not in use.

# yum erase openldap-servers

The openldap-servers RPM is not installed by default on RHEL6 machines. It is needed only by the OpenLDAP server, not by the clients which use LDAP for authentication. If the system is not intended for use as an LDAP Server it should be removed.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19491r377045_chk'
  tag severity: 'low'
  tag gid: 'V-218010'
  tag rid: 'SV-218010r603264_rule'
  tag stig_id: 'RHEL-06-000256'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19489r377046_fix'
  tag 'documentable'
  tag legacy: ['V-38627', 'SV-50428']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
