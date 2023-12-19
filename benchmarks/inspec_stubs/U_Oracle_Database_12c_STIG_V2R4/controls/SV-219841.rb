control 'SV-219841' do
  title 'Connections by mid-tier web and application systems to the Oracle DBMS from a DMZ or external network must be encrypted.'
  desc 'Multi-tier systems may be configured with the database and connecting middle-tier system located on an internal network, with the database located on an internal network behind a firewall and the middle-tier system located in a DMZ. In cases where either or both systems are located in the DMZ (or on networks external to DoD), network communications between the systems must be encrypted.'
  desc 'check', 'Review the System Security Plan for remote applications that access and use the database.

For each remote application or application server, determine whether communications between it and the DBMS are encrypted. If any are not encrypted, this is a finding.'
  desc 'fix', 'Configure communications between the DBMS and remote applications/application servers to use DoD-approved encryption.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21552r533062_chk'
  tag severity: 'medium'
  tag gid: 'V-219841'
  tag rid: 'SV-219841r533064_rule'
  tag stig_id: 'O121-BP-023000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21551r533063_fix'
  tag 'documentable'
  tag legacy: ['SV-75937', 'V-61447']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
