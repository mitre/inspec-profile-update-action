control 'SV-216541' do
  title 'The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code use d for authentication to cryptographic modules.'
  desc 'check', 'Review the router configuration to verify that SSH version 2 is configured as shown in the example below.

ssh server v2

Note: IOS XR supports SSHv1 and SSHv2. SSHv1 uses Rivest, Shamir, and Adelman (RSA) keys while SSHv2 uses Digital Signature Algorithm (DSA) keys which is FIPS 186-4.

If the Cisco router is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions, this is a finding.'
  desc 'fix', 'Configure the router to use SSH version 2 as shown in the example below.

RP/0/0/CPU0:R3(config)#ssh server v2'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17776r288309_chk'
  tag severity: 'high'
  tag gid: 'V-216541'
  tag rid: 'SV-216541r879784_rule'
  tag stig_id: 'CISC-ND-001200'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-17773r288310_fix'
  tag 'documentable'
  tag legacy: ['SV-105611', 'V-96473']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
