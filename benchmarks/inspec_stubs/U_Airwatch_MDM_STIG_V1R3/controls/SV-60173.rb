control 'SV-60173' do
  title 'If the AirWatch MDM Server includes a mobile email management capability, the email client must either block or convert all active content in email (HTML, RTF, etc.) to text before the email is forwarded to the mobile device.'
  desc "HTML embedded in an email has the potential to host malicious code that may allow an attacker access to the user's end device and possibly the network to which it is attached. Requiring that all emails are viewed in plain text protects against malicious code that could be embedded in the HTML content of an email."
  desc 'check', 'Ensure the mobile email server/client either blocks or converts all active content in email (HTML, RTF, etc.) to text before the email is forwarded to the mobile device. Talk to the site system administrator and have them confirm this capability exists in the AirWatch MDM Server. Also, review the AirWatch MDM Server configuration. If the mobile email client does not either block or convert all active content in email (HTML, RTF, etc.) to text before the email is forwarded to the mobile device, this is a finding.

Samsung Knox MOS: To verify that HTML mail is deactivated from the administration console: (1) Click "Menu" on top tool bar, (2) click "Profiles" under "Profiles and Policies" heading, (3) locate and click on applicable email profile. Ensure settings under "Exchange Active Sync" section meet this requirement.'
  desc 'fix', 'Configure the AirWatch MDM Server to either block or convert all active content in email (HTML, RTF, etc.) to text before the email is forwarded to the mobile device. 

To establish Exchange Active Sync Profile denying HTML mail from the administration console:  (1) Click "Menu" on top tool bar, and (2) click "Profiles" under "Profiles and Policies" heading. From the "Select a platform to start" page, (3) choose the operating system in which to create new profile.  After selecting an Operating System, (4) fill out applicable information in "General" tab, and (5) click "Exchange ActiveSync" on the left-hand column.  (6) Click "Configure", (7) fill in appropriate Exchange Server information, (8) and uncheck box labeled "Enable HTML Mail".  (9) Click "Save and Assign".'
  impact 0.3
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50067r2_chk'
  tag severity: 'low'
  tag gid: 'V-47301'
  tag rid: 'SV-60173r1_rule'
  tag stig_id: 'ARWA-03-000020'
  tag gtitle: 'SRG-APP-196-MDM-217-MEM'
  tag fix_id: 'F-51007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000086']
  tag nist: ['AC-19 d']
end
