control 'SV-43159' do
  title 'The IE TLS parameter must be set correctly.'
  desc 'This parameter ensures  only DoD-approved ciphers and algorithms are enabled for use by the web browser. TLS is a protocol for protecting communication between the browser and the target server.  When the browser attempts to set up a protected communication with the target server, the browser and server negotiate which protocol and version to use.  The browser and server attempt to match each other’s list of supported protocols and versions and pick the most preferred match.'
  desc 'check', %q(Open Internet Explorer. From the menu bar, select "Tools". From the "Tools" drop-down menu, select "Internet Options". 
From the "Internet Options" window, select the "Advanced" tab, from the "Advanced" tab window scroll down to the 
"Security" category. Verify a checkmark is placed in 'Use TLS 1.0' or higher check boxes. Verify there is not a check 
placed in the check box for 'Use SSL 2.0' or 'Use SSL 3.0'. If 'Use SSL 2.0' or 'Use SSL 3.0' is checked, then this 
is a finding. 
1) The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet 
Explorer-> Internet Control Panel-> Advanced Page-> 'Turn off Encryption Support' must be 'Enabled' and ensure the 
option selected is 'Use TLS 1.0' or higher' from the drop-down box. If the selected options contain 'SSL 2.0' 
or 'SSL 3.0', then this is a finding.
2) The policy value for Computer Configuration -> Administrative Templates -> Internet Explorer -> Security Features -> 'Allow fallback to SSL 3.0 (Internet Explorer)' must be selected, and 'No Sites' selected from the drop-down box.)
  desc 'fix', %q(Open Internet Explorer. From the menu bar, select "Tools". From the "Tools" drop-down menu, select "Internet Options". 
From the "Internet Options" window, select the "Advanced" tab, from the "Advanced" tab window scroll down to the 
"Security" category. Place a checkmark in the 'Use TLS 1.0' or higher check boxes. Uncheck 'Use SSL 2.0' and 'Use SSL 
3.0' options. 
Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet 
Explorer-> Internet Control Panel-> Advanced Page-> 'Turn off Encryption Support' to 'Enabled', and select 'Use TLS 
1.0' or higher from the drop-down box. Ensure the options do not include 'SSL 2.0' or 'SSL 3.0'.)
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-41147r19_chk'
  tag severity: 'medium'
  tag gid: 'V-6238'
  tag rid: 'SV-43159r5_rule'
  tag stig_id: 'DTBI014'
  tag gtitle: 'DTBI014- IE TLS Setting'
  tag fix_id: 'F-36695r14_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
