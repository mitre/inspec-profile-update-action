control 'SV-215699' do
  title 'The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

NOTE: Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and Government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions.

SSH Example

ip ssh version 2
ip ssh server algorithm mac hmac-sha2-256

If the Cisco router is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions, this is a finding.'
  desc 'fix', 'Configure SSH to use FIPS-validated HMAC for remote maintenance sessions as shown in the following example:

SSH Example

R1(config)#ip ssh version 2
R1(config)#ip ssh server algorithm mac hmac-sha2-256'
  impact 0.7
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16893r835051_chk'
  tag severity: 'high'
  tag gid: 'V-215699'
  tag rid: 'SV-215699r879784_rule'
  tag stig_id: 'CISC-ND-001200'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-16891r835052_fix'
  tag 'documentable'
  tag legacy: ['V-96145', 'SV-105283']
  tag cci: ['CCI-002890', 'CCI-001941']
  tag nist: ['MA-4 (6)', 'IA-2 (8)']
end
