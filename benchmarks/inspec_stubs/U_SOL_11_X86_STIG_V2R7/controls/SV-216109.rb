control 'SV-216109' do
  title 'User accounts must be locked after 35 days of inactivity.'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Operating systems need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise.

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local logon accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.

'
  desc 'check', %q(Determine whether the 35-day inactivity lock is configured properly.

# useradd -D | xargs -n 1 | grep inactive |\
awk -F= '{ print $2 }'

If the command returns a result other than 35, this is a finding.

The root role is required for the "logins" command.

For each configured user name and role name on the system, determine whether a 35-day inactivity period is configured. Replace [username] with an actual user name or role name.

# logins -axo -l [username] | awk -F: '{ print $13 }'


If these commands provide output other than 35, this is a finding.)
  desc 'fix', 'The root role is required.

Perform the following to implement the recommended state:

# useradd -D -f 35

To set this policy on a user account, use the command(s):

# usermod -f 35 [username]

To set this policy on a role account, use the command(s):

# rolemod -f 35 [name]'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-36491r603076_chk'
  tag severity: 'medium'
  tag gid: 'V-216109'
  tag rid: 'SV-216109r603268_rule'
  tag stig_id: 'SOL-11.1-040280'
  tag gtitle: 'SRG-OS-000003'
  tag fix_id: 'F-36455r603077_fix'
  tag satisfies: ['SRG-OS-000003', 'SRG-OS-000118']
  tag 'documentable'
  tag legacy: ['V-48079', 'SV-60951']
  tag cci: ['CCI-000017', 'CCI-000795']
  tag nist: ['AC-2 (3) (d)', 'IA-4 e']
end
