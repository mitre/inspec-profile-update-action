control 'SV-205227' do
  title 'The salt value for zones signed using NSEC3 RRs must be changed every time the zone is completely re-signed.'
  desc 'NSEC3 RRs contain other options than just the (hashed) next name and RRType bitmap. There are also 2 values associated with the NSEC3 RR: the iterations (number of times each name is hashed) and the salt (string appended to each name before hashing). These values are configurable during signing and are used to increase the work necessary by an attacker. Both values should be changed on a regular basis to maintain protection against zone enumeration.

The salt value should be changed every time the entire zone is re-signed. The salt value should be a random string with a length small enough to ensure that appending the salt value to the domain name does not result in a FQDN considered too long for the DNS protocol (a single label in the DNS protocol can be 256 octets). A value between 1 - 15 octets would be acceptable for the majority of cases. Note that zones that are dynamically re-signed as needed may not be able to change the salt for NSEC3 RRs as an automatic process. In these cases, the salt rollover procedure is similar to the key algorithm rollover procedure in that the NSEC3 RR chain with the new salt is generated first (ending with the NSEC3PARAM RR) before removing the old (outgoing) NSEC3 chain.'
  desc 'check', "Check the DNS configuration files and operational documentation. If the zone's RRs have been signed with NSEC3, the operational procedures should stipulate to change the salt value every time the zone is completely re-signed.

If the operational procedures do not specify to change the salt value for RRs signed with NSEC3 every time the zone is completely re-signed, this is a finding."
  desc 'fix', 'Include instructions in the DNS operational procedures to change the salt value every time RRs signed by NSEC3 have been re-signed.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5494r392594_chk'
  tag severity: 'medium'
  tag gid: 'V-205227'
  tag rid: 'SV-205227r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000077'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5494r392595_fix'
  tag 'documentable'
  tag legacy: ['SV-69163', 'V-54917']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
