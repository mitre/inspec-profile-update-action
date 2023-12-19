control 'SV-215598' do
  title 'The Windows 2012 DNS Server must be configured to prohibit or restrict unapproved ports and protocols.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements by providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

On Windows 2012 DNS Server, during DNS resolution, DNS messages are sent from DNS clients to DNS servers or between DNS servers. Messages are sent over UDP and DNS servers bind to UDP port 53. When the message length exceeds the default message size for a User Datagram Protocol (UDP) datagram (512 octets), the first response to the message is sent with as much data as the UDP datagram will allow, and then the DNS server sets a flag indicating a truncated response. The message sender can then choose to reissue the request to the DNS server using TCP (over TCP port 53). The benefit of this approach is that it takes advantage of the performance of UDP but also has a backup failover solution for longer queries.

In general, all DNS queries are sent from a high-numbered source port (49152 or above) to destination port 53, and responses are sent from source port 53 to a high-numbered destination port.'
  desc 'check', 'By default, the Windows 2012 DNS Server listens on TCP 53 and opens UDP ports 53. Also by default, Windows 2012 DNS Server sends from random, high-numbered source ports 49152 and above.

To confirm the listening ports, log onto Windows 2012 DNS Server as an Administrator.
Open a command window with the “Run-as Administrator” option.

In the command window, type the following command:
netstat -a -b |more <enter>

The result is a list of all services running on the server, with the respective “LISTENING TCP” and “OPEN UDP” ports being used.

Find Windows 2012 DNS Server service and verify the State is "LISTENING" on TCP port 53 and that UDP 53 is listed (indicating it is OPEN).

If the server shows UDP 53 in results list and shows TCP port 53 as “LISTENING”, this is not a finding.'
  desc 'fix', 'Re-install DNS.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16792r314269_chk'
  tag severity: 'medium'
  tag gid: 'V-215598'
  tag rid: 'SV-215598r561297_rule'
  tag stig_id: 'WDNS-CM-000029'
  tag gtitle: 'SRG-APP-000142-DNS-000014'
  tag fix_id: 'F-16790r314270_fix'
  tag 'documentable'
  tag legacy: ['SV-73059', 'V-58629']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
