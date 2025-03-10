control 'SV-248813' do
  title 'OL 8 must have the packages required for encrypting offloaded audit logs installed.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Offloading is a common process in information systems with limited audit storage capacity. 
 
OL 8 installation media provides "rsyslogd". This is a system utility providing support for message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols) provides a method to securely encrypt and offload auditing. 
 
Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above. 
 
Examples of each configuration follow: 
UDP *.* @remotesystemname 
TCP *.* @@remotesystemname 
RELP *.* :omrelp:remotesystemname:2514 
 
Note that a port number was given as there is no standard port for RELP.'
  desc 'check', 'Verify the operating system has the packages required for encrypting offloaded audit logs installed with the following commands: 
 
$ sudo yum list installed rsyslog-gnutls 
 
rsyslog-gnutls.x86_64 8.1911.0-6.el8 @AppStream 
 
If the "rsyslog-gnutls" package is not installed, ask the administrator to indicate how audit logs are being encrypted during offloading and what packages are installed to support it.  
 
If there is no evidence of audit logs being encrypted during offloading, this is a finding.'
  desc 'fix', 'Configure the operating system to encrypt offloaded audit logs by installing the required packages with the following command: 
 
$ sudo yum install rsyslog-gnutls'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52247r780003_chk'
  tag severity: 'medium'
  tag gid: 'V-248813'
  tag rid: 'SV-248813r780005_rule'
  tag stig_id: 'OL08-00-030680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52201r780004_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
