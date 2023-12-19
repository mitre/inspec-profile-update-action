control 'SV-251793' do
  title 'The NSX-T Manager must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the Information System Security Officer (ISSO).'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, is important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'From an NSX-T Manager shell, run the following command(s):

> get logging-servers

If any configured logging-servers are not configured with protocol of "tcp", "li-tls", or "tls" and level of "info", this is a finding.

If no logging-servers are configured, this is a finding.

Note: This check must be run from each NSX-T Manager as they are configured individually.'
  desc 'fix', '(Optional) From an NSX-T Manager shell, run the following command(s) to clear any existing incorrect logging-servers:

> clear logging-servers

From an NSX-T Manager shell, run the following command(s) to configure a tcp syslog server:

> set logging-server <server-ip or server-name> proto tcp level info

From an NSX-T Manager shell, run the following command(s) to configure a tls syslog server:

> set logging-server <server-ip or server-name> proto tls level info serverca ca.pem clientca ca.pem certificate cert.pem key key.pem

From an NSX-T Manager shell, run the following command(s) to configure a li-tls syslog server:

> set logging-server <server-ip or server-name> proto li-tls level info serverca root-ca.crt

Note: If  using the protocols TLS or LI-TLS to configure a secure connection to a log server, the server and client certificates must be stored in /image/vmware/nsx/file-store on each NSX-T Manager appliance.'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Manager NDM'
  tag check_id: 'C-55253r810380_chk'
  tag severity: 'high'
  tag gid: 'V-251793'
  tag rid: 'SV-251793r810382_rule'
  tag stig_id: 'TNDM-3X-000096'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-55207r810381_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
