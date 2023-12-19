control 'SV-100913' do
  title 'The vAMI must log all successful login events.'
  desc 'Logging the access to the application server allows the system administrators to monitor user accounts. By logging successful/unsuccessful logons, the system administrator can determine if an account is compromised (e.g., frequent logons) or is in the process of being compromised (e.g., frequent failed logons) and can take actions to thwart the attack. Logging successful logons can also be used to determine accounts that are no longer in use.'
  desc 'check', 'At the command prompt, execute the following command:

grep quiet_success /etc/pam.d/vami-sfcb

If the command returns any output, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/pam.d/vami-sfcb.

Comment out the line which contains quiet_success'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90263'
  tag rid: 'SV-100913r1_rule'
  tag stig_id: 'VRAU-VA-000610'
  tag gtitle: 'SRG-APP-000503-AS-000228'
  tag fix_id: 'F-97005r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
