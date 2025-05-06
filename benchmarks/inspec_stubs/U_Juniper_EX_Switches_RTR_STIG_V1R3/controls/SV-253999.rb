control 'SV-253999' do
  title 'The Juniper router must be configured to have all nonessential capabilities disabled.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'Review the router configuration to determine if services or functions not required for operation, or not related to router functionality (e.g., DNS, email client or server, FTP server, or web server) are enabled.
By default, unnecessary services like finger, telnet, TFTP and FTP are not enabled and will not be listed at [edit system services].

For example, the following services should NOT be enabled as shown:
[edit system services]
finger;
ftp;
rlogin;
telnet;
tftp-server;
web-management;
Note: If the services listed above are marked "inactive", they are not enabled. 

If unnecessary services and functions are enabled on the router, this is a finding.'
  desc 'fix', 'Remove unneeded services and functions from the router. For example:

delete system services finger
delete system services ftp
delete system services rlogin
delete system services telnet
delete system services tftp-server
delete system services web-management

For processes that support disable:
set system processes web-management disable

Removal is recommended because the service or function may be inadvertently enabled otherwise.

However, if removal is not possible, disable the service or function.'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57451r844028_chk'
  tag severity: 'low'
  tag gid: 'V-253999'
  tag rid: 'SV-253999r844030_rule'
  tag stig_id: 'JUEX-RT-000270'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-57402r844029_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
