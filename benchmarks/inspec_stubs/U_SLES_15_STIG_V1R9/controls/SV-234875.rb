control 'SV-234875' do
  title 'The SUSE operating system must not have unnecessary account capabilities.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise. Therefore all necessary non interactive accounts should not have an interactive shell assigned to them.'
  desc 'check', %q(Verify all non-interactive SUSE operating system accounts do not have an interactive shell assigned to them.

Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).

Check the system accounts on the system with the following command:

> awk -F: '($7 !~ "/sbin/nologin" && $7 !~ "/bin/false"){print $1 ":" $3 ":" $7}' /etc/passwd
root:0:/bin/bash
nobody:65534:/bin/bash

If a non-interactive accounts such as "games" or "nobody" is listed with an interactive shell, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system so that all non-interactive accounts on the system have no interactive shell assigned to them.

Run the following command to disable the interactive shell for a specific non-interactive user account:

> sudo usermod --shell /sbin/nologin nobody'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38063r618894_chk'
  tag severity: 'medium'
  tag gid: 'V-234875'
  tag rid: 'SV-234875r622137_rule'
  tag stig_id: 'SLES-15-020091'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38026r618895_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
