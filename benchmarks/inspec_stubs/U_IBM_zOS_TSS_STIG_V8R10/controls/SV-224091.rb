control 'SV-224091' do
  title 'IBM z/OS UNIX security parameters for restricted network service(s) in /etc/inetd.conf must be properly specified.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'From the UNIX System Services ISPF Shell enter
/etc/inetd.conf

If any Restricted Network Services that are listed below are specified or not commented out this is a finding.

RESTRICTED NETWORK SERVICES/PORTS
Service Port
Chargen 19
Daytime 13
Discard 9
Echo 7
Exec 512
finger 79
shell 514
time 37
login 513
smtp 25
timed 525
nameserver 42
systat 11
uucp 540
netstat 15
talk 517
qotd 17
tftp 69'
  desc 'fix', 'Review the settings in The /etc/inetd.conf file determine if every entry in the file represents a service that is actually in use. Services that are not in use must be disabled to reduce potential security exposures.

The following services must be disabled in /etc/inetd.conf unless justified and documented with the ISSO:

RESTRICTED NETWORK SERVICES

Service Port
Chargen 19
Daytime 13
Discard 9
Echo 7
Exec 512
finger 79
shell 514
time 37
login 513
smtp 25
timed 525
nameserver 42
systat 11
uucp 540
netstat 15
talk 517
qotd 17
tftp 69

/etc/inetd.conf

The /etc/inetd.conf file is used by the INETD daemon. It specifies how INETD is to handle service requests on network sockets. Specifically, there is one entry in inetd.conf for each service. Each service entry specifies several parameters. The login_name parameter is of special interest. It specifies the userid under which the forked daemon is to execute. This userid is defined to the ACP and it may require a UID(0) (i.e., superuser authority) value.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25764r516672_chk'
  tag severity: 'medium'
  tag gid: 'V-224091'
  tag rid: 'SV-224091r877929_rule'
  tag stig_id: 'TSS0-US-000180'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25752r516673_fix'
  tag 'documentable'
  tag legacy: ['V-98889', 'SV-107993']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
