control 'SV-33004' do
  title 'The MultiViews directive must be disabled.'
  desc '<0> [object Object]'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directive: Options

Review all uncommented Options statements for the following value: -MultiViews

If the value is found on the Options statement, and it does not have a preceding "-", this is a finding. If the value does not exist at all, this would be a finding unless the enabled Options statement is set to “None”.'
  desc 'fix', 'Add a "-" to the MultiViews setting, or set the options directive to None.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33671r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13734'
  tag rid: 'SV-33004r1_rule'
  tag stig_id: 'WA000-WWA056 W22'
  tag gtitle: 'WA000-WWA056'
  tag fix_id: 'F-29306r1_fix'
end
