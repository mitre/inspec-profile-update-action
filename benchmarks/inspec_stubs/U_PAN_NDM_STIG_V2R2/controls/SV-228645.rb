control 'SV-228645' do
  title 'The Palo Alto Networks security platform must be configured to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

The Palo Alto Networks security platform uses a hardened operating system in which unnecessary services are not present.  The device has a DNS, NTP, update, and e-mail client installed.  Note that these are client applications and not servers; additionally, each has a valid purpose.  However, local policy may dictate that the update service, e-mail client, and statistics (reporting) service capabilities not be used. DNS can be either "Server" or "Proxy"; both are allowed unless local policy declares otherwise. NTP and SNMP are necessary functions.'
  desc 'check', 'Go to Device >> Setup >> Services
In the "Services" window, view which services are configured.
Note: DNS can be either "Server" or "Proxy"; both are allowed unless local policy declares otherwise.
Note: The Palo Alto Networks security platform cannot be a DNS server, only a client or proxy.

NTP is a necessary service.
Note: The Palo Alto Networks security platform cannot be an NTP server, only a client.

Go to Device >> Setup >> Management
In the "Management Interface Settings" window, view the enabled services.
Note: Which management services are enabled.  HTTPS, SSH, ping, and SNMP, are normally allowed.
  
If User-ID, User-ID Syslog Listener-SSL, User-ID Syslog Listener-UDP, or HTTP OCSP is present, verify with the ISSO that this has been authorized.
Go to Device >> Setup >> Operations tab>> Miscellaneous
Select SNMP Setup.
In the "SNMP Setup" window, check if SNMP V3 is selected.
If unauthorized services are configured, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Services
In the "Services" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
Note: DNS can be either "Server" or "Proxy"; both are allowed unless local policy declares otherwise.
Note: The Palo Alto Networks security platform cannot be a DNS server, only a client or proxy.

NTP is a necessary service.
Note: The Palo Alto Networks security platform cannot be an NTP server, only a client.

Go to Device >> Setup >> Management
In the "Management Interface Settings" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Management Interface Settings" window, select HTTP OCSP, HTTPS, SSH,  SNMP, User-ID, User-ID Syslog Listener-SSL, User-ID Syslog Listener-UDP if these protocols will be used.  
Select "OK".
Note: SNMP Versions 1 and 2 are not considered secure; use SNMP Version 3.

Device >> Setup >> Operations tab>> Miscellaneous
Select SNMP Setup.
In the "SNMP Setup" window, select V3. 
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30880r513538_chk'
  tag severity: 'medium'
  tag gid: 'V-228645'
  tag rid: 'SV-228645r513540_rule'
  tag stig_id: 'PANW-NM-000046'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-30857r513539_fix'
  tag 'documentable'
  tag legacy: ['SV-77207', 'V-62717']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
