control 'SV-220503' do
  title 'The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Verify that FIPS mode is enabled as shown in the example below:

fips mode enable

Note: Cisco NX-OS software supports only SSH version 2 (SSHv2). Beginning in Cisco NX-OS Release 5.1, SSH runs in FIPS mode. Source: Cisco Nexus 7000 Series NX-OS Security Configuration Guide, Release 6.x

If the switch is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions, this is a finding.'
  desc 'fix', 'Enable fips mode via the command fips mode enable.'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22218r539230_chk'
  tag severity: 'high'
  tag gid: 'V-220503'
  tag rid: 'SV-220503r879784_rule'
  tag stig_id: 'CISC-ND-001200'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-22207r539231_fix'
  tag 'documentable'
  tag legacy: ['V-101551', 'SV-110655']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
