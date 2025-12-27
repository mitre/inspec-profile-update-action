control 'SV-234150' do
  title 'If communication with the central audit server is lost, the FortiGate firewall must generate a real-time alert to, at a minimum, the SCA and ISSO.'
  desc 'Without a real-time alert (less than a second), security personnel may be unaware of an impending failure of the audit functions and system operation may be adversely impacted. Alerts provide organizations with urgent messages. Automated alerts can be conveyed in a variety of ways, including via a regularly monitored console, telephonically, via electronic mail, via text message, or via websites.

Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. Most firewalls use UDP to send audit records to the server and cannot tell if the server has received the transmission, thus the site must either implement a connection-oriented communications solution (e.g., TCP) or implement a heartbeat with the central audit server and send an alert if it is unreachable.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Security Fabric.
2. Click Automation.
3. Verify Automation Stitches are configured to send alerts related to loss of communication with the central audit server.
4. For each Automation Stitch, verify a valid Action Email has been configured.

If there are no organization-specific Automation Stitches defined to trigger on loss of communication with the central audit server, this is a finding.'
  desc 'fix', 'To create real-time alerts when FortiAnalyzer is the central audit server, log in to the FortiGate GUI with Super-Admin privilege. If not using FortiAnalyzer, skip ahead to the central log server steps. 

1. Click Security Fabric.
2. Click Automation.
3. Click +Create New (Automation Stitch).
4. For Trigger, select FortiOS Event Log.
5. For Event field, Click + (and choose a specific event type).
6. For Action, select Email, specify recipients, and Email subject.
7. Click OK.

The following are all relevant Event Log entries for loss of communication with the central audit server. For most complete coverage, configure an Automation Stitch for each of the Event Log entries below:

-FortiAnalyzer connection down
-FortiAnalyzer connection failed
-FortiAnalyzer log access failed
-Log Upload Error

To create real-time alerts when using a syslog server as the central audit server, log in to the FortiGate GUI with Super-Admin privilege.

To ensure Feature visibility: 
1. Click System.
2. Click Feature Visibility.
3. Under Additional Features, toggle the switch to enable Load Balance.
4. Click Apply.

To configure the alert: 
1. Click Policies & Objects.
2. Click Health Check.
3. Click +Create New.
4. Name the Health Check.
5. For Type, select TCP.
6. For Interval, type {5}.
7. For Timeout, type {1}.
8. For Retry, type {1}.
9. For Port, type {514}.
10. Click OK.
11. Click Virtual Servers.
12. Click +Create New.
13. Name the Virtual Server.
14. For Type, select TCP.
15. For Interface, select any unused internal interface.
16. For Virtual Server IP, type any unused IP.
17. For Virtual Server Port, type {514}.
18. For Health Check, select the Health Check that was created in steps 1-10.
19. In Real Servers, click +Create New.
20. In New Real Server IP Address, type the IP address of the syslog server.
21. For port, type {514}.
22. Click OK to close New Real Server window.
23. Click OK to close Edit Virtual Server.
24. Click Security Fabric.
25. Click Automation.
26. Click +Create New (Automation Stitch).
27. For Trigger, select FortiOS Event Log.
28. For Event field, click + and choose "VIP real server down".
29. For Action, select Email, specify recipients, and Email subject.
30. Click OK.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37335r611448_chk'
  tag severity: 'medium'
  tag gid: 'V-234150'
  tag rid: 'SV-234150r628776_rule'
  tag stig_id: 'FNFG-FW-000105'
  tag gtitle: 'SRG-NET-000335-FW-000017'
  tag fix_id: 'F-37300r611449_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
