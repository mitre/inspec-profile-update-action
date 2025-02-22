control 'SV-223167' do
  title 'Extensions install must be disabled.'
  desc 'A browser extension is a program that has been installed into the browser which adds functionality to it. Where a plug-in interacts only with a web page and usually a third party external application (Flash, Adobe Reader) an extension interacts with the browser program itself. Extensions are not embedded in web pages and must be downloaded and installed in order to work. Extensions allow browsers to avoid restrictions which apply to web pages. For example, an extension can be written to combine data from multiple domains and present it when a certain page is accessed which can be considered Cross Site Scripting. If a browser is configured to allow unrestricted use of extension then plug-ins can be loaded and installed from malicious sources and used on the browser.'
  desc 'check', 'Open a browser window, type "about:config" in the address bar, then navigate to the setting for Preference Name "xpinstall.enabled" and set the value to “false” and locked.

Criteria: If the value of “xpinstall.enabled” is “false”, this is not a finding.

If the value is locked, this is not a finding.

If the SA can show that “DisableSystemAddonUpdate” policy is used instead, and set to “1”, this is not a finding.'
  desc 'fix', 'Set the preference “xpinstall.enabled” to “false” and lock using the “mozilla.cfg” file.  The “mozilla.cfg” file may need to be created if it does not already exist.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24840r754408_chk'
  tag severity: 'medium'
  tag gid: 'V-223167'
  tag rid: 'SV-223167r754409_rule'
  tag stig_id: 'DTBF186'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24828r531319_fix'
  tag 'documentable'
  tag legacy: ['SV-79381', 'V-64891']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
