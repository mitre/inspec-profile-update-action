control 'SV-215205' do
  title 'If LDAP authentication is required, AIX must setup LDAP client to refresh user and group caches less than a day.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'If LDAP authentication is not required, this is Not Applicable.

Verify the "/etc/security/ldap/ldap.cfg" file to see if the following two keywords have a value that is greater than "900" seconds:

# grep -i usercachetimeout /etc/security/ldap/ldap.cfg
usercachetimeout: 900

# grep -i groupcachetimeout /etc/security/ldap/ldap.cfg
groupcachetimeout: 900

If any of the above keywords does not exist, is commented out, or any value of the above keywords are greater than "900", this is a finding.'
  desc 'fix', 'Edit the "/etc/security/ldap/ldap.cfg" file to set the following two keywords to have value of "900":
usercachetimeout
groupcachetimeout

Restart LDAP client using command:
# /usr/sbin/restart-secldapclntd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16403r294066_chk'
  tag severity: 'medium'
  tag gid: 'V-215205'
  tag rid: 'SV-215205r508663_rule'
  tag stig_id: 'AIX7-00-001046'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-16401r294067_fix'
  tag 'documentable'
  tag legacy: ['SV-101645', 'V-91547']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
