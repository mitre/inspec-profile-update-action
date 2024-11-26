control 'SV-252177' do
  title 'MongoDB must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'If MongoDB is configured to authenticate using SASL and LDAP check the saslauthd command line options in the system boot script that starts saslauthd (the location will be dependent on the specific Linux operating system and boot script layout and naming conventions).

If the "-t" option is not set for the "saslauthd" process in the system boot script, this is a finding.'
  desc 'fix', "With MongoDB configured using SASL LDAP authentication and on certain Linux distributions, saslauthd starts with the caching of authentication credentials enabled. 

Until restarted or until the cache expires, saslauthd will not contact the LDAP server to re-authenticate users in its authentication cache. This allows saslauthd to successfully authenticate users in its cache, even in the LDAP server is down or if the cached users' credentials are revoked.

To set the expiration time (in seconds) for the authentication cache, see the -t option of saslauthd (https://www.systutorials.com/docs/linux/man/8-saslauthd/)."
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55633r813911_chk'
  tag severity: 'medium'
  tag gid: 'V-252177'
  tag rid: 'SV-252177r813913_rule'
  tag stig_id: 'MD4X-00-005700'
  tag gtitle: 'SRG-APP-000400-DB-000367'
  tag fix_id: 'F-55583r813912_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
