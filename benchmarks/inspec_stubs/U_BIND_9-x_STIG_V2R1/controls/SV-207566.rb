control 'SV-207566' do
  title 'The BIND 9.X implementation must not utilize a TSIG or DNSSEC key for more than one year.'
  desc 'Cryptographic keys are the backbone of securing DNS information over the wire, maintaining DNS data integrity, and the providing the ability to validate DNS information that is received.

When a cryptographic key is utilized by a DNS server for a long period of time, the likelihood of compromise increases. A compromised key set would allow an attacker to intercept and possibly inject comprised data into the DNS server. In this compromised state, the DNS server would be vulnerable to DoS attacks, as well as being vulnerable to becoming a launching pad for further attacks on an organizations network.'
  desc 'check', 'With the assistance of the DNS Administrator, identify all of the cryptographic key files used by the BIND 9.x implementation.

With the assistance of the DNS Administrator, determine the location of the cryptographic key files used by the BIND 9.x implementation.

# ls –al <Crypto_Key_Location>
-rw-------. 1 named named 76 May 10 20:35 crypto-example.key

If the server is in a classified network, the DNSSEC portion of the requirement is Not Applicable.

For DNSSEC Keys:
Verify that the “Created” date is less than one year from the date of inspection:

Note: The date format will be displayed in YYYYMMDDHHMMSS.

# cat <DNSSEC_Key_File> | grep -i “created”
Created: 20160704235959

If the “Created” date is more than one year old, this is a finding.

For TSIG Keys:

Verify with the ISSO/ISSM that the TSIG keys are less than one year old.

If a TSIG key is more than one year old, this is a finding.'
  desc 'fix', 'Generate new DNSSEC and TSIG keys.

For DNSSEC keys:

Use the newly generated keys to resign all of the zone files on the name server.

For TSIG keys:

Update the named.conf file with the new keys.

Restart the BIND 9.X process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7821r283752_chk'
  tag severity: 'medium'
  tag gid: 'V-207566'
  tag rid: 'SV-207566r612253_rule'
  tag stig_id: 'BIND-9X-001113'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-7821r283753_fix'
  tag 'documentable'
  tag legacy: ['SV-87067', 'V-72443']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
