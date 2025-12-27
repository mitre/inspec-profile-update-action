control 'SV-207704' do
  title 'The Palo Alto Networks security platform must use a Vulnerability Protection Profile that blocks any critical, high, or medium threats.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage.

Detection components that use signatures can detect known attacks by using known attack signatures. Signatures are usually obtained from and updated by the IDPS component vendor. These attacks include SYN-flood, ICMP-flood, and Land Attacks.

This requirement applies to the communications traffic functionality of the IDPS as it pertains to handling communications traffic, rather than to the IDPS device itself.'
  desc 'check', 'Go to  Objects >> Security Profiles >> Vulnerability Protection
If there are no Vulnerability Protection Profiles configured, this is a finding.

Ask the Administrator which  Vulnerability Protection Profile is used for interzone traffic.
View the configured Vulnerability Protection Profiles; check the "Severity" and "Action" columns.
If the Vulnerability Protection Profile used for interzone traffic does not block all critical, high, and medium threats, this is a finding.

Go to Policies >> Security
Review each of the configured security policies in turn.
For any Security Policy that affects traffic between Zones (interzone), view the Profile column.  If the Profile column does not display the  Vulnerability Protection Profile symbol, this is a finding.'
  desc 'fix', 'To create a Vulnerability Protection Profile:
Go to Objects >> Security Profiles >> Vulnerability Protection
Select "Add".
In the "Vulnerability Protection Profile" window, complete the required fields.
In the "Name" field, enter the name of the Vulnerability Protection Profile.
In the "Description" field, enter the description of the Vulnerability Protection Profile.
In the "Rules" tab, select "Add".
In the "Vulnerability Protection Rule" window, 
In the "Rule Name" field, enter the Rule name,
In the "Threat Name" field, select "any",
In the "Action" field, select "block".
In the "Host type" field, select "any",
Select the checkboxes above the "CVE" and "Vendor ID" boxes. 
In the "Severity" section, select the "critical", "high", and "medium" check boxes.
Select "OK".

In the "Vulnerability Protection Profile" window, select the configured rule, then select "OK".
Use the Profile in a Security Policy;
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
Select "OK". 
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7958r358445_chk'
  tag severity: 'medium'
  tag gid: 'V-207704'
  tag rid: 'SV-207704r856618_rule'
  tag stig_id: 'PANW-IP-000043'
  tag gtitle: 'SRG-NET-000362-IDPS-00198'
  tag fix_id: 'F-7958r358446_fix'
  tag 'documentable'
  tag legacy: ['SV-77169', 'V-62679']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
