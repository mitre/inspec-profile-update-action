control 'SV-220607' do
  title 'The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

Non-local maintenance and diagnostic activities are conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Review the Cisco switch configuration to verify that it uses FIPS-validated HMAC to protect the integrity of remote maintenance sessions as shown in the example below:

NOTE: Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and Government standards. Unless required for legacy use, DoD systems should not be configured to use SHA-1 for integrity of remote access sessions.

SSH Example

ip ssh version 2
ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256

If the Cisco switch is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions, this is a finding.'
  desc 'fix', 'Configure SSH to use FIPS-validated HMAC for remote maintenance sessions as shown in the following example:

SSH Example

SW1(config)#ip ssh version 2
SW1(config)#iip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256'
  impact 0.7
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22322r835087_chk'
  tag severity: 'high'
  tag gid: 'V-220607'
  tag rid: 'SV-220607r879784_rule'
  tag stig_id: 'CISC-ND-001200'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-22311r835088_fix'
  tag 'documentable'
  tag legacy: ['SV-110443', 'V-101339']
  tag cci: ['CCI-002890', 'CCI-001941']
  tag nist: ['MA-4 (6)', 'IA-2 (8)']
end
