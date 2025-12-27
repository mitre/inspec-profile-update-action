control 'SV-228843' do
  title 'The Palo Alto Networks security platform must block phone home traffic.'
  desc 'A variety of Distributed Denial of Service (DDoS) attacks and other attacks use "botnets" as an attack vector.  A botnet is a collection of software agents (referred to as "bot"), residing on compromised computers.  Attacks are orchestrated by a "bot herder" to command these agents to launch attacks. Part of the command and control communication between the controller and the bots is a message sent from a bot that informs the controller that it is operating.  This is referred to as a "phone home" message.

On the Palo Alto Networks security platform, a security policy can include an Anti-spyware Profile for “phone home” detection (detection of traffic from installed spyware).  The device has two pre-configured Anti-spyware Profiles; Default and Strict.  The Default Anti-spyware Profile sends an alert for detected phone-home traffic for all severity levels except the low and informational severity threat levels, while the Strict Anti-spyware Profile blocks phone-home traffic for the critical, high, and medium severity threat levels.  

Phone home traffic must either be blocked or intercepted by the DNS Sinkholing feature. Therefore, a custom Anti-spyware Profile or the Strict Anti-spyware Profile must be used instead of the Default Anti-spyware Profile.  Note that there are specific implementation requirements for DNS Sinkholing to operate properly; refer to the Palo Alto Networks documentation for details.'
  desc 'check', 'Ask the Administrator which Anti-Spyware profile is used:
Go to Objects >> Security Profiles >> Anti-Spyware
Select the Anti-Spyware Profile.
In the "Anti-Spyware Profile" window, in the "DNS Signatures" tab, in the Action on "DNS queries" field, if either "block" or "sinkhole" is not selected, this is a finding.

Ask the Administrator which Security Policy Rule allows traffic from client hosts in the trust zone to the untrust zone:
Go to Policies >> Security
Select the identified policy rule.
View the "Security Policy Rule" window.
Select the "Actions" tab.
In the "Profile Setting" section, in the "Anti-Spyware" field, if there is no Anti-Spyware Profile or the Anti-Spyware Profile is not the correct one, this is a finding.'
  desc 'fix', 'Go to Objects >> Security Profiles >> Anti-Spyware
Select the name of a configured Anti-Spyware Profile or select "Add" to create a new one.
In the "Anti-Spyware Profile" window, in the "DNS Signatures" tab, in the Action on "DNS queries" field, select "block" or "sinkhole".    
If "sinkhole" is selected, complete the "Sinkhole IPv4" and "Sinkhole IPv6" fields.

Note: If DNS Sinkholing is used, the device and network must be configured to support it.

If this is a new Anti-Spyware Profile, complete the required fields in all tabs.
Select "OK". 
Use the Anti-Spyware Profile in a Security Policy;
Edit the Security Policy Rule that allows traffic from client hosts in the trust zone to the untrust zone to include the sinkhole zone as a destination and attach the Anti-spyware Profile.  Select or configure a rule that allows traffic from the client host zone to the untrust zone.

Go to Policies >> Security
Select the appropriate existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Anti-Spyware" field, select the configured Anti-Spyware Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31078r513824_chk'
  tag severity: 'medium'
  tag gid: 'V-228843'
  tag rid: 'SV-228843r557387_rule'
  tag stig_id: 'PANW-AG-000049'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-31055r513825_fix'
  tag 'documentable'
  tag legacy: ['V-62569', 'SV-77059']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
