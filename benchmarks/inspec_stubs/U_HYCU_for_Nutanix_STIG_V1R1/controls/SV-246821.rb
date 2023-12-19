control 'SV-246821' do
  title 'The HYCU server must terminate shared/group account credentials when members leave the group.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', 'Within the HYCU Web UI in the Self-Service menu, check for users or groups that no longer need access.

If any old or unused accounts or groups exist, this is a finding.'
  desc 'fix', 'Within the HYCU Web UI, remove the users or groups that no longer need access.
 
If any AD users or groups have been left within the HYCU Web UI in the Self-Service menu, remove users that are no longer needed from their respective AD groups.'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50253r768125_chk'
  tag severity: 'medium'
  tag gid: 'V-246821'
  tag rid: 'SV-246821r768127_rule'
  tag stig_id: 'HYCU-AC-000003'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-50207r768126_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
