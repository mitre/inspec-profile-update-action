control 'SV-90941' do
  title 'The network device must terminate shared/group account credentials when members leave the group.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', 'Review the documentation to verify that a procedure exists to change the account of last resort and root account password when users with knowledge of the password leave the group.

If a procedure does not exist to change the account of last resort and root account password when users with knowledge of the password leave the group, this is a finding.'
  desc 'fix', "Establish and document a procedure that requires the changing of the account of last resort and root account password when users with knowledge of the password leave the group. To change the password:

1. Log on to CounterACT's Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Enter a new password.

Note: Use of a cryptographically generated password is recommended. Password must be stored in a locked safe and used only when necessary since individual accounts are required to be used to ensure non-repudiation."
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75939r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76253'
  tag rid: 'SV-90941r1_rule'
  tag stig_id: 'CACT-NM-000149'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-82889r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
