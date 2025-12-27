control 'SV-215414' do
  title 'The sendmail server must have the debug feature disabled on AIX systems.'
  desc 'Debug mode is a feature present in older versions of Sendmail which, if not disabled, may allow an attacker to gain access to a system through the Sendmail service.'
  desc 'check', 'Check the version of "sendmail" installed on the system using: 
# echo \\$Z | /usr/sbin/sendmail -bt -d0 

The above command should yield the following output:
Version AIX7.2/8.14.4
 Compiled with: DNSMAP LDAPMAP LDAP_REFERRALS LOG MAP_REGEX MATCHGECOS
                MILTER MIME7TO8 MIME8TO7 NAMED_BIND NDBM NETINET NETINET6
                NETUNIX NEWDB NIS NISPLUS PIPELINING SCANF USERDB USE_LDAP_INIT
                USE_TTYPATH XDEBUG

If the "sendmail" reported version is less than "8.6", this is a finding.'
  desc 'fix', 'Obtain and install a more recent version of "Sendmail", which does not implement the DEBUG feature.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16612r294693_chk'
  tag severity: 'medium'
  tag gid: 'V-215414'
  tag rid: 'SV-215414r508663_rule'
  tag stig_id: 'AIX7-00-003116'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16610r294694_fix'
  tag 'documentable'
  tag legacy: ['V-91661', 'SV-101759']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
