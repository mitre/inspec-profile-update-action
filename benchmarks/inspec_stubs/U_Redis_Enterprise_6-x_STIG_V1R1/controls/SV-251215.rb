control 'SV-251215' do
  title 'Redis Enterprise DBMS must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', 'To check this control, investigate the application documentation and understand what services and ports are in use within the application. Inspect the ports running on the server using the following command:
sudo ss -tulw

If any ports or services that are not approved are present in the output of this command, this is a finding.

Redis Enterprise makes use of the following ports:
1. TCP 1968, Internal, Proxy traffic
2. TCP 3333, 3334, 3335, 3336, 3337, 3338, 3339, 36379, 36380, Internal, Cluster traffic
3. TCP 8001, Internal, External, Sentinel Traffic
4. TCP 8002, 8004, Internal, System health monitoring
5. TCP 8443 Internal, External, User Interface
6. TCP 8444, 9080, Internal, Proxy Traffic
7. TCP 9081. Internal, Active-Active        
8. TCP 8070, 8071, Internal & External, Metrics Exporter
9. TCP 9443 (Recommended), 8080 (Recommended to be removed), REST API traffic
10. TCP  10000-19999, Internal, External, Active-Active Database traffic
11. TCP  20000-29999, Internal
12. UDP 53, 5353, Internal, External        DNS/mDNS traffic'
  desc 'fix', 'Use firewalld commands to remove any unnecessary ports from the appropriate zone. To do this, enter the following commands as root.

This command will immediately remove a port from the configuration:
$ firewall-cmd --zone=<zone> --remove-port=<port>/<protocol>

This command will persistently remove a port from a configuration:
$ firewall-cmd --permanent --zone=<zone> --remove-port=<port>/<protocol>

Repeat the previous commands for any port that is unauthorized for use or is not used.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54650r804833_chk'
  tag severity: 'medium'
  tag gid: 'V-251215'
  tag rid: 'SV-251215r804835_rule'
  tag stig_id: 'RD6X-00-007900'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-54604r804834_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
