control 'SV-77029' do
  title 'ColdFusion must enable Global Script Protection.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry field and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

Invalid inputs are also used for Cross-Site Scripting (XSS) attacks.  This type of attack relies on the attacker being able to insert script code into an input field and having the script executed on the client machine.  By enabling Global Script Protection, there is a very limited protection against certain Cross-Site Scripting attack vectors.  It is important to understand that enabling this setting does not protect hosted applications from all possible Cross-Site Scripting attacks. 

When this setting is turned on, it uses a regular expression defined in the file neo-security.xml to replace input variables containing the following tags: object, embed, script, applet, and meta with Invalid Tag.  This setting does not restrict any JavaScript strings that may be injected and executed, iframe tags, or any XSS obfuscation techniques."
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If the "Enable Global Script Protection" is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Check "Enable Global Script Protection" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62539'
  tag rid: 'SV-77029r1_rule'
  tag stig_id: 'CF11-06-000224'
  tag gtitle: 'SRG-APP-000447-AS-000273'
  tag fix_id: 'F-68459r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
