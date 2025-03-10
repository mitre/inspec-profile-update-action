control 'SV-82543' do
  title 'The A10 Networks ADC must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

Of the three authentication protocols for device management on the A10 Networks ADC, none are inherently replay-resistant. If LDAP or TACACS+ is selected, TLS must also be used. If RADIUS is used, the device must be a FIPS mode platform.'
  desc 'check', 'Review the device configuration.

Since the device supports RADIUS, TACACS+, and LDAP, one of these must be configured. The following is a sample verification for TACACS+.

The following command shows the parts of the configuration with the word "tacplus":
show run | inc tacplus

If the output is blank, this is a finding.

The following command shows information for all configured TACACS servers:
show tacacs-server

If no servers are configured, this is a finding.

If RADIUS is used, ask the Administrator whether or not the device is a FIPS version of the platform. This is identified by the designation "FIPS" in the stock keeping unit (SKU).

The following command shows the version of ACOS used and other related information:
show version

If the output does not include "Platform features: fips", this is a finding.'
  desc 'fix', 'Since the device supports RADIUS, TACACS+, and LDAP, one of these must be configured. The following is a sample configuration for TACACS+.

The following command sets the authentication method to TACACS+ for administrative access to the device:
authentication type tacplus

The local database (local option) must be included as one of the authentication sources, regardless of the order is which the sources are used. Authentication using only a remote server is not supported.

The following command configures the device to use a TACACS+ server:
tacacs-server host [hostname | ipaddr] secret [secret-string]
"hostname | ipaddr" is the hostname or IP address of the TACACS+ server.
"secret-string" is the secret key to authenticate the switch to the TACACS+ server.

Up to two TACACS+ servers can be configured. The secondary server is used only if the primary server does not respond. The servers are used in the order in which you add them to the configuration. Use a separate command for each of the servers.

If RADIUS is used, the device must be the FIPS version of the platform. The FIPS version of the platform is identified by the designation "FIPS" in the stock keeping unit (SKU) when purchasing the device. It is imperative that the correct version of the device be procured.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68053'
  tag rid: 'SV-82543r1_rule'
  tag stig_id: 'AADC-NM-000052'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-74169r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
