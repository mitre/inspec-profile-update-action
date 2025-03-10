control 'SV-13608' do
  title 'Written procedures for the replacement of cryptographic keys used to secure DNS transactions does not exist.'
  desc 'Without adequate TSIG supersession procedures, there is the potential that an unauthorized person may be able to compromise the key.  Once in possession of the key, that individual might be able to update DNS records by configuring a machine to masquerade as a zone partner.  Since name servers are configured to accept updates signed by a valid key, there may be no other administrative or technical controls to prevent this type of security breach.'
  desc 'check', 'Windows

This check should be marked not applicable for all windows servers.  Windows utilizes Active Directory for it’s key management or no keys at all.

BIND

Like user account passwords, cryptographic keys such as TSIG keys must be changed periodically to minimize the probability that they will be compromised.  If there is a known compromise of a TSIG key, then it needs to be replaced immediately.  One of the most important aspects of key supersession is the method that will be used to transfer newly generated keys.  Possibilities, in rough order of preference, are as follows:

- SSH
- Encrypted e-mail using DoD PKI certificates 
- Secure fax (STU-III)
- Regular mail (using the expedited mailing service holding the current GSA contract for "small package overnight delivery service")
- Hand courier

Instruction:  If there are no procedures for TSIG key supersession, then this is a finding.  If there are such procedures, then it must cover the following:

- Frequency of key supersession
- Criteria for triggering emergency supersession events
- Notification of relevant personnel during emergency and non-emergency supersession
- Methods for securely transferring newly generated keys

This is a finding if any of these elements are missing from the supersession procedures.'
  desc 'fix', 'The IAO should establish standard operating procedures for TSIG key supersession.  These procedures should include, at a minimum, frequency of key supersession, criteria for triggering emergency supersession events, notification of relevant personnel during emergency and non-emergency supersession, and methods for securely transferring newly generated keys.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3363r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13040'
  tag rid: 'SV-13608r1_rule'
  tag stig_id: 'DNS0145'
  tag gtitle: 'Key supersession procedures are inadequate.'
  tag fix_id: 'F-4345r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
