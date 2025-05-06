control 'SV-208932' do
  title 'The openldap-servers package must not be installed unless required.'
  desc 'Unnecessary packages should not be installed to decrease the attack surface of the system.'
  desc 'check', 'To verify the "openldap-servers" package is not installed, run the following command: 

$ rpm -q openldap-servers

The output should show the following. 

package openldap-servers is not installed

If it does not, this is a finding.'
  desc 'fix', 'The "openldap-servers" package should be removed if not in use. Is this machine the OpenLDAP server? If not, remove the package. 

# yum erase openldap-servers

The openldap-servers RPM may be installed.  It is needed only by the OpenLDAP server, not by clients which use LDAP for authentication.  If the system is not intended for use as an LDAP server, it should be removed.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9185r357776_chk'
  tag severity: 'low'
  tag gid: 'V-208932'
  tag rid: 'SV-208932r603263_rule'
  tag stig_id: 'OL6-00-000256'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9185r357777_fix'
  tag 'documentable'
  tag legacy: ['SV-65027', 'V-50821']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
