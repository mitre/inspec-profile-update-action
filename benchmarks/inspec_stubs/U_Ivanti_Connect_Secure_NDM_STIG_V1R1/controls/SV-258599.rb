control 'SV-258599' do
  title 'The ICS must be configured to send admin log data to a redundant central log server.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.

'
  desc 'check', 'Verify the ICS is configured with address information so it sends admin log event records to a central log server.

In the ICS Web UI, navigate to System >> Log/Monitoring >> Events >> Settings. 

Under "Syslog Servers", verify a server name/IP address, facility of LOCAL0, type TLS, and the management source interface are defined.

In the ICS Web UI, navigate to System >> Log/Monitoring >> Admin Access >> Settings.

Under "Syslog Servers", verify server names/IP addresses are added. Also ensure facility of LOCAL0, type TLS, and them management source interface are not defined.

If the ICS is not configured to send log admin log events data to redundant central log servers, this is a finding.'
  desc 'fix', 'Configure the ICS with the address information for the redundant central log servers. 

In the ICS Web UI:
1. Navigate to System >> Log/Monitoring >> Events >> Settings.
2. Under "Syslog Servers" add an IP address/server name/IP.
3. Set the facility to LOCAL0.
4. Set type to TLS.
5. If a client cert is required for the syslog server, select the client certificate to use for the syslog traffic. If none exists, import the DOD-signed client key pair to the ICS under System >> Configuration >> Certificates >> Client Auth Certificates.
6. Set the standard filer.
7. Set the source interface as the management interface.
8. Click "Add".
9. Click "Save Changes".
10. Repeat these steps for the admin logs under System >> Log/Monitoring >> Admin Access >> Settings.
11. Repeat these steps to add a redundant syslog server.'
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62339r930483_chk'
  tag severity: 'high'
  tag gid: 'V-258599'
  tag rid: 'SV-258599r930485_rule'
  tag stig_id: 'IVCS-NM-000030'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-62248r930484_fix'
  tag satisfies: ['SRG-APP-000516-NDM-000350', 'SRG-APP-000360-NDM-000295', 'SRG-APP-000515-NDM-000325']
  tag 'documentable'
  tag cci: ['CCI-001851', 'CCI-001858', 'CCI-002605']
  tag nist: ['AU-4 (1)', 'AU-5 (2)', 'SI-2 c']
end
