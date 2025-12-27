control 'SV-104487' do
  title 'Symantec ProxySG must configure Web Management Console access restrictions to authorized IP address/ranges.'
  desc 'It is important that administrative access (SSH, web) to an appliance using the account of last resort be able to be restricted to only the appropriate networks/subnets in order to reduce the likelihood of unauthorized access.'
  desc 'check', 'Verify console access using the account of last resort has been restricted to specific networks/subnets.

1. Log on to the Web Management Console.
2. Click >> Configuration >> Authentication >> Console Access.
3. Confirm that the correct networks/subnets are specified in the list.

If there are no entries in the list, this is a finding.'
  desc 'fix', 'Configure console access using the account of last resort to specific networks/subnets.

1. Log on to the Web Management Console.
2. Click Configuration >> Authentication >> Console Access.
3. Click "New".
4. Enter the IP address and subnet mask for the desired network and click "OK".
5. Repeat step 4 until all desired networks have been added.
6. Click "Apply".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93847r1_chk'
  tag severity: 'high'
  tag gid: 'V-94657'
  tag rid: 'SV-104487r1_rule'
  tag stig_id: 'SYMP-NM-000030'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-100775r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
