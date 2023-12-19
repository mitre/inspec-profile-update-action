control 'SV-246923' do
  title 'ONTAP must be configured to create a session lock after 15 minutes.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device. Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock. Once invoked, the session lock must remain in place until the administrator re-authenticates. No other system activity aside from re-authentication must unlock the management session.

Note that CCI-001133 requires that administrative network sessions be disconnected after 10 minutes of idle time. This requirement may only apply to local administrative sessions.'
  desc 'check', 'Use "system timeout show" to check the current CLI timeout value is 15 minutes.

If the system timeout is not configured to 15, this is a finding.'
  desc 'fix', 'Configure the CLI timeout value to 15 minutes with the command, "system timeout modify -timeout 15".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50355r769099_chk'
  tag severity: 'medium'
  tag gid: 'V-246923'
  tag rid: 'SV-246923r769101_rule'
  tag stig_id: 'NAOT-AC-000002'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag fix_id: 'F-50309r769100_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
