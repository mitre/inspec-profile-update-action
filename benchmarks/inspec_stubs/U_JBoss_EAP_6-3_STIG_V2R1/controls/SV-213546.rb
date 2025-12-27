control 'SV-213546' do
  title 'The JBoss server, when hosting mission critical applications, must be in a high-availability (HA) cluster.'
  desc "A MAC I system is a system that handles data vital to the organization's operational readiness or effectiveness of deployed or contingency forces.  A MAC I system must maintain the highest level of integrity and availability.  By HA clustering the application server, the hosted application and data are given a platform that is load-balanced and provides high availability."
  desc 'check', 'Interview the system admin and determine if the applications hosted on the application server are mission critical and require load balancing (LB) or high availability (HA).

If the applications do not require LB or HA, this requirement is NA.

If the documentation shows the LB or HA services are being provided by another system other than the application server, this requirement is NA.

If applications require LB or HA, request documentation from the system admin that identifies what type of LB or HA configuration has been implemented on the application server.

Ask the system admin to identify the components that require protection.  Some options are included here as an example.  Bear in mind the examples provided are not complete and absolute and are only provided as examples.  The components being made redundant or HA by the application server will vary based upon application availability requirements.

Examples are:
Instances of the Application Server
Web Applications
Stateful, stateless and entity Enterprise Java Beans (EJBs)
Single Sign On (SSO) mechanisms
Distributed Cache
HTTP sessions
JMS and Message Services.

If the hosted application requirements specify LB or HA and the JBoss server has not been configured to offer HA or LB, this is a finding.'
  desc 'fix', 'Configure the application server to provide LB or HA services for the hosted application.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14769r296304_chk'
  tag severity: 'medium'
  tag gid: 'V-213546'
  tag rid: 'SV-213546r615939_rule'
  tag stig_id: 'JBOS-AS-000640'
  tag gtitle: 'SRG-APP-000435-AS-000069'
  tag fix_id: 'F-14767r296305_fix'
  tag 'documentable'
  tag legacy: ['SV-76809', 'V-62319']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
