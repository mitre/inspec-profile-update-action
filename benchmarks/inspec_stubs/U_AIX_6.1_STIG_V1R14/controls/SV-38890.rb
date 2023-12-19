control 'SV-38890' do
  title 'The SNMP service must require the use of a FIPS 140-2 approved cryptographic hash algorithm as part of its authentication and integrity methods.'
  desc 'The SNMP service must use SHA-1 or a FIPS 140-2 approved successor for authentication and integrity.'
  desc 'check', 'Check all SNMPv3 users for configured authentication protocols.

# grep USM_USER /etc/snmpdv3.conf

The 4th field contains the hash used in the authentication protocol.  If an entry exists that does not use HMAC-SHA for the authentication protocol, this is a finding.'
  desc 'fix', 'Edit the /etc/snmpdv3.conf file.  Change any instances of the HMAC-MD5 authentication protocol in USM_USER entries to HMAC-SHA.  For all changed USM_USER entries, regenerate authentication keys using the "pwtokey" command and replace the keys in the /etc/snmpdv3.conf file.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37888r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22448'
  tag rid: 'SV-38890r1_rule'
  tag stig_id: 'GEN005306'
  tag gtitle: 'GEN005306'
  tag fix_id: 'F-33137r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
