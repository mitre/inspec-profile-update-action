control 'SV-24675' do
  title 'DBA roles should be periodically monitored to detect assignment of unauthorized or excess privileges.'
  desc 'Excess privilege assignment can lead to intentional or unintentional unauthorized actions. Such actions may compromise the operation or integrity of the DBMS and its data. Monitoring assigned privileges assists in the detection of unauthorized privilege assignment. The DBA role is assigned privileges that allow DBAs to modify privileges assigned to them. Ensure that the DBA Role is monitored for any unauthorized changes.'
  desc 'check', 'Review documented procedures and implementation evidence of DBA role privilege monitoring.

If procedures are not documented or noted in the System Security Plan or are not complete, this is a Finding.

If evidence of implementation for monitoring does not exist, this is a Finding.

If monitoring does not occur monthly (~30 days) or more often, this is a Finding.'
  desc 'fix', 'Design, document and implement procedures for monitoring DBA role privilege assignments.

Grant the DBA role the minimum privileges required to perform administrative functions.

Establish monitoring of DBA role privileges monthly or more often.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29192r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15106'
  tag rid: 'SV-24675r1_rule'
  tag stig_id: 'DG0086-ORACLE11'
  tag gtitle: 'DBMS DBA role privilege monitoring'
  tag fix_id: 'F-26208r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
