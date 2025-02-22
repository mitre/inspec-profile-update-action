control 'SV-253804' do
  title 'The Tanium application must authenticate endpoint devices (servers) before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk, such as remote connections.

This requires device-to-device authentication. Information systems must use IEEE 802.1x, Extensible Authentication Protocol [EAP], Radius server with EAP-Transport Layer Security [TLS] authentication, or Kerberos to identify/authenticate devices on local and/or wide area networks.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Platform Settings".

4. In the "Filter items" search box, type "TLSMode" and "ReportingTLSMode".

5. Click "Enter".

If results are returned and "TLSMode" = 0 and "ReportingTLSMode" = 0, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Platform Settings".

4. In the "Filter items" search box, type "TLSMode" and "ReportingTLSMode".

5. Click "Enter".

6. Change the value for both "TLSMode" and "ReportingTLSMode" to "1".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57256r842438_chk'
  tag severity: 'medium'
  tag gid: 'V-253804'
  tag rid: 'SV-253804r850330_rule'
  tag stig_id: 'TANS-00-001780'
  tag gtitle: 'SRG-APP-000580'
  tag fix_id: 'F-57207r842439_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
