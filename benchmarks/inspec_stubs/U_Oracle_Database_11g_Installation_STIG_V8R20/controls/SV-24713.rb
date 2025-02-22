control 'SV-24713' do
  title 'The DBMS restoration priority should be assigned.'
  desc 'When DBMS service is disrupted, the impact it has on the overall mission of the organization can be severe. Without proper assignment of the priority placed on restoration of the DBMS and its subsystems, restoration of DBMS services may not meet mission requirements.'
  desc 'check', 'Review the System Security Plan to discover the restoration priority assigned to the DBMS.

If a restoration priority is not assigned, this is a Finding.'
  desc 'fix', 'Review the mission criticality of the DBMS in relation to the overall mission of the organization and assign it a restoration priority.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29347r1_chk'
  tag severity: 'low'
  tag gid: 'V-15145'
  tag rid: 'SV-24713r1_rule'
  tag stig_id: 'DG0108-ORACLE11'
  tag gtitle: 'DBMS restoration priority'
  tag fix_id: 'F-26372r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
