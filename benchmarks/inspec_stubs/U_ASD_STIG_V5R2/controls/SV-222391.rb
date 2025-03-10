control 'SV-222391' do
  title 'Applications requiring user access authentication must provide a logoff capability for user initiated communication session.'
  desc 'If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker.  Applications providing user access must provide the ability for users to manually terminate their sessions and log off.'
  desc 'check', 'If the application does not provide an interface for interactive user access, this is not applicable.

Log on to the application with a valid user account. Examine the user interface. Identify the command or link that provides the logoff function.

Activate the user logoff function.

Observe user interface and attempt to interact with the application.  Confirm user interaction with the application is no longer possible.

If the user session is not terminated or if the logoff function does not exist, this is a finding.'
  desc 'fix', 'Design and configure the application to provide all users with the capability to manually terminate their application session.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24061r493081_chk'
  tag severity: 'medium'
  tag gid: 'V-222391'
  tag rid: 'SV-222391r849419_rule'
  tag stig_id: 'APSC-DV-000090'
  tag gtitle: 'SRG-APP-000296'
  tag fix_id: 'F-24050r493082_fix'
  tag 'documentable'
  tag legacy: ['SV-83869', 'V-69247']
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
