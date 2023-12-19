control 'SV-4506' do
  title 'The shared secret in the APP session(s) was not a randomly generated 32 character text string.'
  desc 'The core requirements related to zone transfers are that an authoritative name server transfers zone information only to designated zone partners and that name servers only accept zone data when it is cryptographically authenticated.

CSS APP provides means to designate which devices it can share zone data and to authenticate those transactions.  CSS devices can define their peers using IP addresses and authenticate them using Challenge Handshake Authentication Protocol (CHAP) with a shared secret.  This setup also can be supplemented with MD5 hashing encryption.  While this configuration does not provide the equivalent strength of cryptographic authentication as BINDs TSIG HMAC-MD5, it does provide a satisfactory level of information assurance when CSS DNS operates within a trusted network environment.'
  desc 'check', 'Interview the SA and determine if the key was randomly generated 32-character text string.'
  desc 'fix', 'The CSS DNS administrator should use the following command while in global command mode; app session ip_address authChallenge shared_secret encryptMd5hash.  In this command, ip_address refers to the IP address of the designated peer and the shared_secret is a text string up to 32 characters in length.'
  impact 0.3
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3387r1_chk'
  tag severity: 'low'
  tag gid: 'V-4506'
  tag rid: 'SV-4506r1_rule'
  tag stig_id: 'DNS0900'
  tag gtitle: 'Unsecured shared secret in the APP session(s).'
  tag fix_id: 'F-4391r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
end
