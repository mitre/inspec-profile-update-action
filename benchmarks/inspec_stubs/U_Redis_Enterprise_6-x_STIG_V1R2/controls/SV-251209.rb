control 'SV-251209' do
  title 'Redis Enterprise DBMS must enforce access restrictions associated with changes to the configuration of Redis Enterprise DBMS or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Redis Enterprise is an application database and not intended to be used by human actors. Human actor activity has been generally abstracted to a control plane that resides outside of the database level. 

Redis Enterprise comes with roles for both the control plane and the data plane. Viewer roles and none provide access restrictions to make configuration changes to the database. 

To verify that users are in the appropriate role, perform the following steps:
1. Log in to the Redis Enterprise Control Plane.
2. Navigate to the access control tab.
3. Navigate to the users tab. 
4. Verify that all users are assigned an appropriate role. If the principle is using custom roles, this may require investigating the permissions provided for each custom role.

If it does not enforce access restrictions associated with changes to the configuration of the DBMS or database(s), this is a finding.'
  desc 'fix', 'Redis Enterprise is an application database and not intended to be used by human actors. Human actor activity has been generally abstracted to a control plane that resides outside of the database level. 

To ensure that users are in the appropriate role, perform the following steps:
1. Log in to the Redis Enterprise Control Plane.
2. Navigate to the access control tab.
3. Navigate to the users tab. 
4. Ensure that the principle is assigned the appropriate permissions for their function.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54644r804815_chk'
  tag severity: 'medium'
  tag gid: 'V-251209'
  tag rid: 'SV-251209r855610_rule'
  tag stig_id: 'RD6X-00-007100'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-54598r804816_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
