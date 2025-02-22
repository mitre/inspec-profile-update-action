control 'SV-223166' do
  title 'Firefox is configured to allow JavaScript to disable or replace context menus.'
  desc 'A context menu (also known as a pop-up menu) is often used in a graphical user interface (GUI) and appears upon user interaction (e.g., a right mouse click). A context menu offers a limited set of choices that are available in the current state, or context, of the operating system or application.  A website may execute JavaScript that can make changes to these context menus.  This can help disguise an attack.  Set this preference to "false" so that webpages will not be able to affect the context menu event.'
  desc 'check', 'Type "about:config" in the address bar of the browser.

Verify that the preferences "dom.event.contextmenu.enabled" is set and locked to "false".

Criteria: If the parameter is set incorrectly, then this is a finding.

If the setting is not locked, this is a finding.'
  desc 'fix', 'Ensure the preferences "dom.event.contextmenu.enabled" is set and locked to "false".'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24839r531315_chk'
  tag severity: 'medium'
  tag gid: 'V-223166'
  tag rid: 'SV-223166r612236_rule'
  tag stig_id: 'DTBF183'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24827r531316_fix'
  tag 'documentable'
  tag legacy: ['SV-16928', 'V-15986']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
