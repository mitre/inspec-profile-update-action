control 'SV-217340' do
  title 'The Juniper router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. 

Currently, HMAC is the only FIPS-approved algorithm for generating and verifying message/data authentication codes in accordance with FIPS 198-1. Products that are FIPS 140-2 validated will have an HMAC that meets specification; however, the option must be configured for use as the only message authentication code used for authentication to cryptographic modules.

Separate requirements for configuring applications and protocols used by each application (e.g., SNMPv3, SSHv2, NTP, HTTPS, and other protocols and applications that require server/client authentication) are required to implement this requirement. Where SSH is used, the SSHv2 protocol suite is required because it includes Layer 7 protocols such as SCP and SFTP, which can be used for secure file transfers.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

system {
…
…
…
    }
    services {
        ssh {
            protocol-version v2;
            macs hmac-sha2-256;
        }
    }

If the router is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions, this is a finding.'
  desc 'fix', 'Configure SSH to use FIPS-validated HMAC for remote maintenance sessions as shown in the following example:

[edit system services]
set ssh protocol-version v2
set ssh macs hmac-sha2-256'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18567r296598_chk'
  tag severity: 'high'
  tag gid: 'V-217340'
  tag rid: 'SV-217340r855881_rule'
  tag stig_id: 'JUNI-ND-001190'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-18565r296599_fix'
  tag 'documentable'
  tag legacy: ['SV-101269', 'V-91169']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
