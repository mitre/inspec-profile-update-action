control 'SV-207708' do
  title 'The Palo Alto Networks security platform must generate an alert to the ISSO and ISSM, at a minimum, when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites).

The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.'
  desc 'check', 'Obtain the list of network services that have not been authorized or approved by the ISSM and ISSO.  For each prohibited network service, view the security policies that denies traffic associated with it and logs the denied traffic. 
Ask the Administrator how the ISSO and ISSM are receiving alerts (E-mail, SNMP Trap, or Syslog).

View the configured Server Profile; if there is no Server Profile for the method explained, this is a finding.
 
View the Log Forwarding Profiles; this is under Objects >> Log Forwarding.  Determine which Server Profile is associated with each Log Forwarding Profile.
View the Security Policies that are used to block unauthorized network services.
Go to Policies >> Security
Select the name of the security policy to view it. 
In the "Actions" tab, in the "Log Setting" section, view the Log Forwarding Profile.

If there is no Log Forwarding Profile, this is a finding.'
  desc 'fix', 'Obtain the list of network services that have not been authorized or approved by the ISSM and ISSO.  For each prohibited network service, configure a security policy that  generates an alert to, at a minimum, the ISSO and ISSM when unauthorized network services are detected.
Configure a Server Profile for use with Log Forwarding Profile(s);  if email is used, the ISSO and ISSM must be recipients.
   
To create an email server profile:
Go to Device >> Server Profiles >> Email
Select "Add". 
In the Email Server Profile, enter the name of the profile.
Select "Add".
In the "Servers" tab, enter the required information:
In the "Name" field, enter the name of the Email server
In the "Email Display Name" field, enter the name shown in the "From" field of the email.
In the "From" field, enter the From email address.
In the "To" field, enter the email address of the recipient.
In the "Additional Recipient" field, enter the email address of another recipient. You can only add one additional recipient. To add multiple recipients, add the email address of a distribution list.
In the "Gateway" field, enter the IP address or host name of the Simple Mail Transport Protocol (SMTP) server used to send the email.
Select "OK".
  
Configure a Log Forwarding Profile; this is under Objects >> Log Forwarding
Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
In the "Actions" tab, select the Log forwarding profile and select "Log at Session End".
"Log at Session Start" may be selected under specific circumstances, but "Log at Session End" is preferred.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7962r358457_chk'
  tag severity: 'medium'
  tag gid: 'V-207708'
  tag rid: 'SV-207708r557390_rule'
  tag stig_id: 'PANW-IP-000048'
  tag gtitle: 'SRG-NET-000385-IDPS-00211'
  tag fix_id: 'F-7962r358458_fix'
  tag 'documentable'
  tag legacy: ['SV-77177', 'V-62687']
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
