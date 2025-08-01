control 'SV-225233' do
  title 'Trust must be established prior to enabling the loading of remote code in .Net 4.'
  desc '<0> [object Object]'
  desc 'check', 'Open Windows explorer and search for *.exe.config.

Search each config file found for the "loadFromRemoteSources" element.

If the loadFromRemoteSources element is enabled  
("loadFromRemoteSources enabled = true"), and the remotely loaded application is not run in a sandboxed environment, or if OS based software controls, such as AppLocker or Software Security Policies, are not utilized, this is a finding.'
  desc 'fix', '.Net application code loaded from a remote source must be run in a controlled environment.  

A controlled environment consists of a sandbox, such as running in an Internet Explorer host environment or employing OS based software access controls, such as AppLocker or Software Security Policies, when application design permits.  

Obtain documented IAO approvals for all remotely loaded code.'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26932r468014_chk'
  tag severity: 'medium'
  tag gid: 'V-225233'
  tag rid: 'SV-225233r849748_rule'
  tag stig_id: 'APPNET0065'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-26920r468015_fix'
  tag legacy: ['SV-41010', 'V-30968']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
