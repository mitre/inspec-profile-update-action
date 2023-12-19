control 'SV-24750' do
  title 'Unauthorized access to external database objects should be removed from application user roles.'
  desc 'Access to objects stored and/or executed outside of the DBMS security context may provide an avenue of attack to host system resources not controlled by the DBMS. Any access to external resources from the DBMS can lead to a compromise of the host system or its resources.'
  desc 'check', 'Review definitions and access restrictions to objects stored outside of DBMS control.

View object application data types defined in the database, but stored outside of the DBMS.

View data objects that include host file and directory references in their definitions.

If any external objects exist that are not referenced and authorized in the System Security Plan, this is a Finding.'
  desc 'fix', 'Evaluate the associated risk in allowing access to external objects.

Consider the security context under which the object is accessed or whether the privileges required to access the object are available for assignment based on job function.

Where feasible, modify the application to use only objects stored internally to the database.

Where not feasible, note the risk assessment and acceptance in the System Security Plan for access to external objects.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-24315r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15105'
  tag rid: 'SV-24750r1_rule'
  tag stig_id: 'DG0120-ORACLE11'
  tag gtitle: 'DBMS application user access to external objects'
  tag fix_id: 'F-25686r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
