control 'SV-204814' do
  title 'The application server, when a MAC I system, must be in a high-availability (HA) cluster.'
  desc "A MAC I system is a system that handles data vital to the organization's operational readiness or effectiveness of deployed or contingency forces.  A MAC I system must maintain the highest level of integrity and availability.  By HA clustering the application server, the hosted application and data are given a platform that is load-balanced and provided high-availability."
  desc 'check', 'If the application server is not a MAC I system, this requirement is NA.

Review the application server documentation and configuration to determine if the application server is part of an HA cluster.

If the application server is not part of an HA cluster, this is a finding.'
  desc 'fix', 'If the application server is not a MAC I system, this requirement is NA.

Configure the application server to be part of an HA cluster.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4934r283083_chk'
  tag severity: 'medium'
  tag gid: 'V-204814'
  tag rid: 'SV-204814r879806_rule'
  tag stig_id: 'SRG-APP-000435-AS-000069'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-4934r283084_fix'
  tag 'documentable'
  tag legacy: ['SV-71807', 'V-57531']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
