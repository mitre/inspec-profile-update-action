control 'SV-82619' do
  title 'The Mainframe Product must terminate shared/group account credentials when members leave the group.'
  desc 'If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. A shared/group account credential is a shared form of authentication that allows multiple individuals to access the application using a single account. There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If Shared/group credentials are not terminated when members leave the group, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to terminate shared/group account credentials when members leave the group.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68687r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68129'
  tag rid: 'SV-82619r1_rule'
  tag stig_id: 'SRG-APP-000317-MFP-000034'
  tag gtitle: 'SRG-APP-000317-MFP-000034'
  tag fix_id: 'F-74245r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
