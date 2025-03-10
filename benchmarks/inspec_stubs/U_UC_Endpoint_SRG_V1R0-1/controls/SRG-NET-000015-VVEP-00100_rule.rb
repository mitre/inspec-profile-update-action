control 'SRG-NET-000015-VVEP-00100_rule' do
  title 'The Unified Communications Endpoint must not be configured with any vendor default accounts, PINs, or passwords to access configuration settings.'
  desc 'Many Unified Communications Endpoints can set or display configuration settings in the instrument itself. This presents a risk if a user obtains information such as the IP addresses and URLs of system components. This obtained information could be used to facilitate an attack on the system. Therefore, these devices should be considered a target to be defended against individuals that would collect voice network information for illicit purposes. To mitigate information gathering by the adversaries, measures must be taken to protect this information.'
  desc 'check', 'Verify the Unified Communications Endpoint does not use the default PIN or password to access configuration settings.

If the Unified Communications Endpoint uses the default PIN or password to access configuration settings, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to not use the default PIN or password to access configuration settings.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000015-VVEP-00100_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000015-VVEP-00100'
  tag rid: 'SRG-NET-000015-VVEP-00100_rule'
  tag stig_id: 'SRG-NET-000015-VVEP-00100'
  tag gtitle: 'SRG-NET-000015-VVEP-00100'
  tag fix_id: 'F-SRG-NET-000015-VVEP-00100_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
