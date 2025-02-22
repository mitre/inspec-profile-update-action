control 'SV-202087' do
  title 'The network device must terminate shared/group account credentials when members leave the group.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', 'Determine if the network device terminates shared/group account credentials when members leave the group.  This requirement may be verified by demonstration, configuration review, or validated test results. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. This requirement is not applicable if the device does not support shared/group credentials. If the network device does not terminate shared/group credentials when members leave the group, this is a finding.'
  desc 'fix', 'Configure the network device to terminate shared/group account credentials when members leave the group.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2213r381863_chk'
  tag severity: 'medium'
  tag gid: 'V-202087'
  tag rid: 'SV-202087r879694_rule'
  tag stig_id: 'SRG-APP-000317-NDM-000282'
  tag gtitle: 'SRG-APP-000317'
  tag fix_id: 'F-2214r381864_fix'
  tag 'documentable'
  tag legacy: ['SV-69447', 'V-55201']
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
