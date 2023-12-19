control 'SV-228642' do
  title 'The Palo Alto Networks security platform must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.  

By default, the Configuration Log contains the administrator username, client (Web or CLI), and date and time for any changes to configurations and for configuration commit actions.  The System Log also shows both successful and unsuccessful attempts for configuration commit actions.

The System Log and Configuration Log can be configured to send log messages by severity level to specific destinations; the Panorama management console, an SNMP console, an e-mail server, or a syslog server.  Since both the System Log and Configuration Log contain information concerning the use of privileges, both must be configured to send messages to a syslog server at a minimum.'
  desc 'check', 'Go to Device >> Log Settings >> System
If any severity level does not have a Syslog Profile, this is a finding.'
  desc 'fix', 'Create a syslog server profile. 
Go to Device >> Server Profiles >> Syslog
Select "Add" 
In the "Syslog Server Profile", enter the name of the profile; select "Add".
In the "Servers" tab, enter the required information.
Name: Name of the syslog server
Server: Server IP address where the logs will be forwarded to
Port: Default port 514
Facility: Select from the drop down list
Select "OK".

Go to Device >> Log Settings >> System
For each severity level, select which destinations should receive the log messages.
Note: The "Syslog Profile" field must be completed.

Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30877r513530_chk'
  tag severity: 'medium'
  tag gid: 'V-228642'
  tag rid: 'SV-228642r513532_rule'
  tag stig_id: 'PANW-NM-000024'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-30854r513531_fix'
  tag 'documentable'
  tag legacy: ['SV-77201', 'V-62711']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
