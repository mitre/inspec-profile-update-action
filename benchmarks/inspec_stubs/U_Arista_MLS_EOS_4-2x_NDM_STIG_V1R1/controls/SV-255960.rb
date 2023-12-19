control 'SV-255960' do
  title 'The Arista network devices must use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.

'
  desc 'check', 'Determine if the Arista network device is configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions.

NOTE: Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DOD systems should not be configured to use SHA-1 for integrity of remote access sessions.

Verify the HMAC settings for SSH using the following command:

switch#sh run | section management ssh

mac hmac-sha2-256 hmac-sha2-512

If the Arista network device does not implement replay-resistant authentication mechanisms for network access to privileged accounts, this is a finding.'
  desc 'fix', 'Configure the Arista network device to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions.

switch(config)#management ssh
switch(config-mgmt-ssh)#mac hmac-sha2-256 hmac-sha2-512
switch(config-mgmt-ssh)#exit'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59636r882220_chk'
  tag severity: 'high'
  tag gid: 'V-255960'
  tag rid: 'SV-255960r882222_rule'
  tag stig_id: 'ARST-ND-000690'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-59579r882221_fix'
  tag satisfies: ['SRG-APP-000411-NDM-000330', 'SRG-APP-000156-NDM-000250']
  tag 'documentable'
  tag cci: ['CCI-001941', 'CCI-002890']
  tag nist: ['IA-2 (8)', 'MA-4 (6)']
end
