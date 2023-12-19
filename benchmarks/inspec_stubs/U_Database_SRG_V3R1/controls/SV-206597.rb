control 'SV-206597' do
  title 'The DBMS must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review DBMS vendor documentation with respect to its ability to enforce access restrictions associated with changes to the configuration of the DBMS or database(s).

If it is not able to do this, this is a finding.

Review the security configuration of the DBMS and database(s).

If it does not enforce access restrictions associated with changes to the configuration of the DBMS or database(s), this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of enforcing access restrictions associated with changes to the configuration of the DBMS or database(s).

Configure the DBMS to enforce access restrictions associated with changes to the configuration of the DBMS or database(s).'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6857r291459_chk'
  tag severity: 'medium'
  tag gid: 'V-206597'
  tag rid: 'SV-206597r617447_rule'
  tag stig_id: 'SRG-APP-000380-DB-000360'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-6857r291460_fix'
  tag 'documentable'
  tag legacy: ['V-58125', 'SV-72555']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
