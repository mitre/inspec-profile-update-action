control 'SV-248817' do
  title 'OL 8 must authenticate the remote logging server for offloading audit logs.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Offloading is a common process in information systems with limited audit storage capacity. 
 
OL 8 installation media provides "rsyslogd". This is a system utility providing support for message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols) provides a method to securely encrypt and offload auditing. 
 
"Rsyslog" supported authentication modes include the following: 
anon - anonymous authentication 
x509/fingerprint - certificate fingerprint authentication 
x509/certvalid - certificate validation only 
x509/name - certificate validation and subject name authentication

'
  desc 'check', %q(Verify the operating system authenticates the remote logging server for offloading audit logs with the following command: 
 
$ sudo grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
 
/etc/rsyslog.conf:$ActionSendStreamDriverAuthMode x509/name 
 
If the value of the "$ActionSendStreamDriverAuthMode" option is not set to "x509/name" or the line is commented out, ask the System Administrator to indicate how the audit logs are offloaded to a different system or media.  
 
If there is no evidence that the transfer of the audit logs being offloaded to another system or media is encrypted, this is a finding.)
  desc 'fix', 'Configure the operating system to authenticate the remote logging server for offloading audit logs by setting the following option in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf": 
 
$ActionSendStreamDriverAuthMode x509/name'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52251r780015_chk'
  tag severity: 'medium'
  tag gid: 'V-248817'
  tag rid: 'SV-248817r780017_rule'
  tag stig_id: 'OL08-00-030720'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-52205r780016_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
