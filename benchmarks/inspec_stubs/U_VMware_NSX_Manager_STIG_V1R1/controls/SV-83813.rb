control 'SV-83813' do
  title 'The NSX Manager must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.
 
Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify NSX Manager audit records are off-loaded to a different system.
 
Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Syslog Server >> Edit. 

Enter name or IP of the Syslog Server, Port, and Protocol.

If audit records are not configured and are not off-loaded to a different system, this is a finding.

Note: TCP is the preferred protocol configuration to protect against network outages and queues logs locally until network connection is restored to a centralized server.'
  desc 'fix', "Change the logs in NSX Manager to send to a centralized server for use as part of the organization's security incident tracking and analysis.
 
Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Syslog Server >> Edit.

Enter name or IP of the Syslog Server, Port, and Protocol."
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69649r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69209'
  tag rid: 'SV-83813r1_rule'
  tag stig_id: 'VNSX-ND-000128'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-75395r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
