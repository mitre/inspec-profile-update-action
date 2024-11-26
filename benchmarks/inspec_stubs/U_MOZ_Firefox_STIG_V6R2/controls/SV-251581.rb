control 'SV-251581' do
  title 'Firefox encrypted media extensions must be disabled.'
  desc 'Enable or disable Encrypted Media Extensions and optionally lock it.

If "Enabled" is set to "false", Firefox does not download encrypted media extensions (such as Widevine) unless the user consents to installing them.

If "Locked" is set to "true" and "Enabled" is set to "false", Firefox will not download encrypted media extensions (such as Widevine) or ask the user to install them.

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to advertising software or browser plug-ins that are not related to requirements or provide a wide array of functionality not required for every mission but that cannot be disabled.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "EncryptedMediaExtensions" is not displayed under Policy Name or the Policy Value does not have "Enabled" set to "false" or the Policy Value does not have "Locked" set to "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Encrypted Media Extensions
Policy Name: Enable Encrypted Media Extensions
Policy State: Disabled
Policy Name: Lock Encrypted Media Extensions
Policy State: Enabled

macOS "plist" file:
<key>EncryptedMediaExtensions</key>
  <dict>
    <key>Enabled</key>
    <false/>
    <key>Locked</key>
    <true/> 

Linux "policies.json" file:
Add the following in the policies section:
"EncryptedMediaExtensions": {
  "Enabled": false,
  "Locked": true
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55016r807213_chk'
  tag severity: 'medium'
  tag gid: 'V-251581'
  tag rid: 'SV-251581r807215_rule'
  tag stig_id: 'FFOX-00-000037'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54970r807214_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
