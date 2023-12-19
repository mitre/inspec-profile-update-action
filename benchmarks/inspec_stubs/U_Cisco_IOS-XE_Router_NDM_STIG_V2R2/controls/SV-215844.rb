control 'SV-215844' do
  title 'The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

SSH Example

ip ssh version 2
ip ssh server algorithm mac hmac-sha1-96

HTTPS Example

ip http secure-server
ip http secure-ciphersuite aes-128-cbc-sha 
ip http secure-client-auth
ip http secure-trustpoint CA_XXX

If the Cisco router is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions, this is a finding.'
  desc 'fix', 'The Cisco router is not compliant with this requirement. However, the risk associated with this requirement can be fully mitigated if the router is configured.

Configure SSH and HTTPs to use FIPS-validated HMAC for remote maintenance sessions as shown in the following examples:

SSH Example

R1(config)#ip ssh version 2
R1(config)#ip ssh server algorithm mac hmac-sha1-96

HTTPS Example

R2(config)#ip http secure-ciphersuite aes-128-cbc-sha'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17083r287571_chk'
  tag severity: 'high'
  tag gid: 'V-215844'
  tag rid: 'SV-215844r531083_rule'
  tag stig_id: 'CISC-ND-001200'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-17081r287572_fix'
  tag 'documentable'
  tag legacy: ['SV-105465', 'V-96327']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
