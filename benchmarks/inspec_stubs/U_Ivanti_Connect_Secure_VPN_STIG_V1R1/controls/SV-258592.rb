control 'SV-258592' do
  title 'The ICS must be configured to send user traffic log data to redundant central log server.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.

This requirement applies only to components where this is specific to the function of the device (e.g., IDPS sensor logs, firewall logs). This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify user access log events are being sent to the central log server.

In the ICS Web UI, navigate to System >> Log/Monitoring >> User Access >> Settings.
1. Under "Select Events to Log", verify all items are checked.
2. Under "Syslog Servers", verify redundant server name/IP address, facility of LOCAL0, type TLS, and the source interface are defined.

If the ICS must be configured to send admin log data to redundant central log server, this is a finding.'
  desc 'fix', 'Direct user access log events to the central log server.

In the ICS Web UI, navigate to System >> Log/Monitoring >> User Access >> Settings.
1. Under "Select Events to Log", check all items.
2. Under "Syslog Servers", add an IP address/server name/IP.
3. Set the facility to "LOCAL0".
4. Set type to "TLS".
5. If a client cert is required for the syslog server, select the client certificate to use for the syslog traffic. If none exists, import the DOD-signed client key pair to the ICS under System >> Configuration >> Certificates >> Client Auth Certificates.
6. Set the standard filer.
7. Set the source interface as either the management or internal interface.
8. Click "Add".
9. Click "Save Changes".
10. Repeat these steps to add a redundant syslog server for user log events.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62332r930462_chk'
  tag severity: 'medium'
  tag gid: 'V-258592'
  tag rid: 'SV-258592r930464_rule'
  tag stig_id: 'IVCS-VN-000305'
  tag gtitle: 'SRG-NET-000334-VPN-001260'
  tag fix_id: 'F-62241r930463_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
