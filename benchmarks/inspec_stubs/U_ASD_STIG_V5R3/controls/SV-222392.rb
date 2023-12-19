control 'SV-222392' do
  title 'The application must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user is not explicitly notified that their application session has been terminated, they cannot be certain that their session did not remain open. Applications with a user access interface must provide an explicit logoff message to the user upon successful termination of the user session.'
  desc 'check', 'If the application does not provide an interface for interactive user access, this is not applicable.

Log on to the application with a valid user account. Examine the user interface. Identify the command or link that provides the logoff function.

Activate the user logoff function.

If the application does not provide an explicit logoff message indicating the user session has been terminated, this is a finding.'
  desc 'fix', 'Design and configure the application to provide an explicit logoff message to users indicating a successful logoff has occurred upon user session termination.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24062r493084_chk'
  tag severity: 'low'
  tag gid: 'V-222392'
  tag rid: 'SV-222392r879675_rule'
  tag stig_id: 'APSC-DV-000100'
  tag gtitle: 'SRG-APP-000297'
  tag fix_id: 'F-24051r493085_fix'
  tag 'documentable'
  tag legacy: ['SV-83871', 'V-69249']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
