control 'SV-217166' do
  title 'If Network Security Services (NSS) is being used by the SUSE operating system it must prohibit the use of cached authentications after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'If NSS is not used on the operating system, this is Not Applicable.

If NSS is used by the SUSE operating system, verify it prohibits the use of cached authentications after one day.

Check that cached authentications cannot be used after one day with the following command:

# sudo grep -i "memcache_timeout" /etc/sssd/sssd.conf

memcache_timeout = 86400

If "memcache_timeout" has a value greater than "86400", or is missing, this is a finding.'
  desc 'fix', 'Configure NSS, if used by the SUSE operating system, to prohibit the use of cached authentications after one day. 

Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[nss]":

memcache_timeout = 86400'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18394r369654_chk'
  tag severity: 'medium'
  tag gid: 'V-217166'
  tag rid: 'SV-217166r603262_rule'
  tag stig_id: 'SLES-12-010670'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-18392r369655_fix'
  tag 'documentable'
  tag legacy: ['V-77183', 'SV-91879']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
