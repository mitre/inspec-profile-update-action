control 'SV-251787' do
  title 'The NSX-T Manager must be configured to send logs to a central log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
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

From an NSX-T Manager shell, run the following command(s) to configure an li-tls syslog server:

> set logging-server <server-ip or server-name> proto li-tls level info serverca root-ca.crt

Note: If using the protocols TLS or LI-TLS to configure a secure connection to a log server, the server and client certificates must be stored in /image/vmware/nsx/file-store on each NSX-T Manager appliance.'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Manager NDM'
  tag check_id: 'C-55247r810362_chk'
  tag severity: 'medium'
  tag gid: 'V-251787'
  tag rid: 'SV-251787r879886_rule'
  tag stig_id: 'TNDM-3X-000088'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-55201r810363_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
