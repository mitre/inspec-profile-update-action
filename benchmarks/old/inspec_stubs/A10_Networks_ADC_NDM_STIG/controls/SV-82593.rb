control 'SV-82593' do
  title 'The A10 Networks ADC must employ centrally managed authentication server(s).'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.

You can configure the device to use remote servers for Authentication, Authorization, and Accounting (AAA) for administrative sessions. The device supports RADIUS, TACACS+, and LDAP servers.'
  desc 'check', 'Review the device configuration.

Since the device supports RADIUS, TACACS+, and LDAP, one of these must be configured. The following is a sample verification for TACACS+.

The following command shows the parts of the configuration with the word "tacplus":
show run | inc tacplus

If the output is blank, this is a finding.

The following command shows information for all configured TACACS servers:
show tacacs-server

If no servers are configured, this is a finding.'
  desc 'fix', 'Since the device supports RADIUS, TACACS+, and LDAP, one of these must be configured. The following is a sample configuration for TACACS+.

The following command sets the authentication method to TACACS+ for administrative access to the device:
authentication type tacplus

The local database (local option) must be included as one of the authentication sources, regardless of the order in which the sources are used. Authentication using only a remote server is not supported.

The following command configures the device to use a TACACS+ server:
tacacs-server host [hostname | ipaddr] secret [secret-string]
"hostname | ipaddr" is the hostname or IP address of the TACACS+ server.
"secret-string" is the secret key to authenticate the switch to the TACACS+ server.

Up to two TACACS+ servers can be configured. The secondary server is used only if the primary server does not respond. The servers are used in the order in which you add them to the configuration. Use a separate command for each of the servers.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68663r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68103'
  tag rid: 'SV-82593r1_rule'
  tag stig_id: 'AADC-NM-000137'
  tag gtitle: 'SRG-APP-000516-NDM-000338'
  tag fix_id: 'F-74217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
