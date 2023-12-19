control 'SV-237826' do
  title 'User credentials which would allow remote access to the system by the Service Processor must be removed from the storage system.'
  desc "Failure to remove the default user accounts associated with remote access from the Service Processor increases the risk of unauthorized access to the 3PAR OS via the product's remote support interface.

The Service Processor's authentication methods have not been evaluated and using such mechanisms to permit remote, full control of the system by organizational or non-organizational users represents an increased risk to unauthorized access.

The Service Processor can also send system data offsite providing access to system information to non-DoD organizations."
  desc 'check', 'Verify Service Processor credentials are not present.

cli% showuser

If any of the users, "3parbrowse", "3paredit", or "3parservice" exist, this is a finding'
  desc 'fix', 'Remove the Service Processor credentials from the storage system. Enter the following command:

cli% removespcredential

Note: This removes the "3paredit", "3parbrowse", and "3parservice" users, and sets the "3parsvc" password to a new random value.'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41036r647885_chk'
  tag severity: 'high'
  tag gid: 'V-237826'
  tag rid: 'SV-237826r647903_rule'
  tag stig_id: 'HP3P-32-001504'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-40995r647886_fix'
  tag 'documentable'
  tag legacy: ['SV-85127', 'V-70505']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
