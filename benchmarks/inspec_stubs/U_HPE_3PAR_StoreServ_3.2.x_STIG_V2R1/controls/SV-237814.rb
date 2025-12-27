control 'SV-237814' do
  title 'The CIM service must be disabled, unless needed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify that CIM is not running with the following command:

cli% showcim

Review the requirements by the Information Owner to determine whether the site requires a CIM management client in order to meet mission objectives.

If the output does not report the CIM "Service" is "Disabled" and there is no documented requirement for this usage, this is a finding.

If the output does not report the CIM service "State" is "Inactive" and there is no documented requirement for this usage, this is a finding.'
  desc 'fix', 'Disable the non-essential CIM feature and remove the associated account with the following commands:

cli% stopcim -f
CIM server stopped successfully.

cli% removeuser 3parcimuser

Confirm the operation with "y".'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41024r647849_chk'
  tag severity: 'medium'
  tag gid: 'V-237814'
  tag rid: 'SV-237814r647851_rule'
  tag stig_id: 'HP3P-32-001002'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-40983r647850_fix'
  tag 'documentable'
  tag legacy: ['SV-85107', 'V-70485']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
