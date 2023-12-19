control 'SV-90909' do
  title 'CounterACT must employ automated mechanisms to centrally apply authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which leads to delays in remediating production problems and addressing compromises in a timely fashion.'
  desc 'check', 'Review the network device configuration to determine if it employs automated mechanisms to centrally apply authentication settings.

1. Connect to the User Directory Console user interface.
2. Select Tools >> Options >> User Directory.
3. Verify the Active Directory configuration exists and tests pass by selecting the chosen directory and selecting "Test".

If authentication settings are not applied centrally using automated mechanisms, this is a finding.'
  desc 'fix', 'Configure CounterACT to employ automated mechanisms to centrally apply authentication settings.

1. Connect to the User Directory Console user interface.
2. Select Tools >> Options >> User Directory.
3. Add the configuration to the Active Directory configuration, select the chosen directory, and select "Test".'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76221'
  tag rid: 'SV-90909r1_rule'
  tag stig_id: 'CACT-NM-000044'
  tag gtitle: 'SRG-APP-000516-NDM-000337'
  tag fix_id: 'F-82857r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000371']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
