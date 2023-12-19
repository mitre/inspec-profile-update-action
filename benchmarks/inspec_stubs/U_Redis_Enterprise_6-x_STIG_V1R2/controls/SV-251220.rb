control 'SV-251220' do
  title 'Redis Enterprise DBMS must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', 'To check this control, investigate the application documentation and understand what services and ports are in use within the application. Inspect the ports running on the server using the following command:
sudo ss -tulw

If any ports or services that are not approved are present in the output of this command, this is a finding.

Redis Enterprise makes use of the following ports:
1. TCP 1968, Internal, Proxy traffic
2. TCP 3333, 3334, 3335, 3336, 3337, 3338, 3339, 36379, 36380, Internal, Cluster traffic
3. TCP 8001, Internal, External, Sentinel Traffic
4. TCP 8002, 8004, Internal, System health monitoring
5. TCP 8443, Internal, External, User Interface
6. TCP 8444, 9080, Internal, Proxy Traffic
7. TCP 9081, Internal, Active-Active        
8. TCP 8070, 8071, Internal & External, Metrics Exporter
9. TCP 9443 (Recommended), 8080 (Recommended to be removed), REST API traffic
10. TCP 10000-19999, Internal, External, Active-Active Database traffic
11. TCP 20000-29999, Internal
12. UDP 53, 5353, Internal, External        DNS/mDNS traffic'
  desc 'fix', 'Use firewalld commands to remove any unnecessary ports from the appropriate zone. To do this, enter the following commands as root:

This command will immediately remove a port from the configuration:
$ firewall-cmd --zone=<zone> --remove-port=<port>/<protocol>

This command will persistently remove a port from a configuration:
$ firewall-cmd --permanent --zone=<zone> --remove-port=<port>/<protocol>

Repeat the previous commands for any port that is unauthorized for use or is not used.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54655r804848_chk'
  tag severity: 'medium'
  tag gid: 'V-251220'
  tag rid: 'SV-251220r804850_rule'
  tag stig_id: 'RD6X-00-008400'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-54609r804849_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
