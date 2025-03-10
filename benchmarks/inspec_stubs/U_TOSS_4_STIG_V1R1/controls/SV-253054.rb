control 'SV-253054' do
  title 'TOSS must have the packages required for offloading audit logs installed.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

TOSS installation media provides "rsyslogd."  "rsyslogd" is a system utility providing support for message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging. Couple this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS, and DTLS protocols), and now there is a method to securely encrypt and off-load auditing.

Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.
Examples of each configuration:
UDP *.* @remotesystemname
TCP *.* @@remotesystemname
RELP *.* :omrelp:remotesystemname:2514
Note that a port number was given as there is no standard port for RELP.'
  desc 'check', 'Verify the operating system has the packages required for offloading audit logs installed with the following commands:

$ sudo yum list installed rsyslog

rsyslog.x86_64          8.2102.0-5.el8          @AppStream

If the "rsyslog" package is not installed, ask the administrator to indicate how audit logs are being offloaded and what packages are installed to support it. If there is no evidence of audit logs being offloaded, this is a finding.'
  desc 'fix', 'Configure the operating system to offload audit logs by installing the required packages with the following command:

$ sudo yum install rsyslog'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56507r824832_chk'
  tag severity: 'medium'
  tag gid: 'V-253054'
  tag rid: 'SV-253054r824834_rule'
  tag stig_id: 'TOSS-04-031370'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56457r824833_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
