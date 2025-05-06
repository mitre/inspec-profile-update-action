control 'SV-86051' do
  title 'The CA API Gateway must off-load audit records onto a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

The CA API Gateway must include a method for off-loading audit records onto a centralized log server, including External Audit Stores and Centralized Syslog Servers.'
  desc 'check', 'By default, audit records are created locally on the CA API Gateway Server and will need to be configured for off-loading using the External Audit Store Wizard or by specifying to send them to a Syslog server via TCP, UDP, or SSL.

If they are not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Select "Tasks" and chose "Manage Log/Audit Sinks". 

Double-click the "ssg" log and change the "Type:" to "Syslog".

Click "Syslog Settings" and specify the settings for the Centralized Syslog Server as defined by the organization.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71427'
  tag rid: 'SV-86051r1_rule'
  tag stig_id: 'CAGW-GW-000590'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-77745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
