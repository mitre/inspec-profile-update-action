control 'SV-239930' do
  title 'The Cisco ASA must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of non-local maintenance and diagnostic communications.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Non-local maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'SSH Example

Step 1: Verify that FIPS mode is enabled as shown in the example below. 

fips enable

Step 2: Verify that SSH is configured to only use FIPS-compliant ciphers and that Diffie-Hellman Group 14  is used for the key exchange as shown in the example below.

ssh version 2
ssh cipher encryption fips
ssh key-exchange group dh-group14-sha1

Note: The ASA only supports SSHv2.

SNMP Example

snmp-server group NETOPS v3 auth 
snmp-server user FWADMIN NETOPS v3 engineID xxxxxxxxxxxx encrypted auth sha xxxxxxxxxxxxxxxx 
snmp-server host NDM_INTERFACE 10.1.48.10  version 3 FWADMIN

If the ASA is not configured to implement cryptographic mechanisms to protect the integrity of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'SSH Example

Step 1: Enable FIPS mode via the fips enable command.

Step 2: Configure SSH to only use FIPS-compliant ciphers and Diffie-Hellman Group 14 for the key exchange.

ASA(config)# ssh cipher encryption fips 
ASA(config)# ssh key-exchange group dh-group14-sha

SNMP Example

ASA(config)# snmp-server group NETOPS v3 auth
ASA(config)# snmp-server user FWADMIN NETOPS v3 auth sha xxxxxxxxxxxxxxx
ASA(config)# snmp-server host NDM_INTERFACE 10.1.48.10  version 3 FWADMIN 
ASA(config)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43163r666151_chk'
  tag severity: 'high'
  tag gid: 'V-239930'
  tag rid: 'SV-239930r666153_rule'
  tag stig_id: 'CASA-ND-001140'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-43122r666152_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
