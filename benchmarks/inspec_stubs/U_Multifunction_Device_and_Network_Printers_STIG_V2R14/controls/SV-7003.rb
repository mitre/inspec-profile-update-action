control 'SV-7003' do
  title 'The default passwords and SNMP community strings of all management services have not been  replaced with complex passwords.'
  desc 'There are many known vulnerabilities in the SNMP protocol and if the default community strings and passwords are not modified an unauthorized individual could gain control of the MFD or printer.  This could lead to a denial of service or the compromise of sensitive data.
The SA will ensure the default passwords and SNMP community strings of all management services are replaced with complex passwords.'
  desc 'check', 'The reviewer will, with assistance from the SA, verify the default passwords and SNMP community strings of all management services have been  replaced with complex passwords.'
  desc 'fix', 'Develop a plan to coordinate the modification of the default passwords and SNMP community strings of all management services replacing them with complex passwords.  Obtain CM approval of the plan and execute the plan.'
  impact 0.7
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2966r2_chk'
  tag severity: 'high'
  tag gid: 'V-6781'
  tag rid: 'SV-7003r2_rule'
  tag stig_id: 'MFD02.001'
  tag gtitle: 'MFD SNMP Community Strings'
  tag fix_id: 'F-6434r1_fix'
  tag 'documentable'
end
