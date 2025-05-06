control 'SV-248814' do
  title 'The OL 8 audit records must be offloaded onto a different system or storage media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. 
 
Offloading is a common process in information systems with limited audit storage capacity. 
 
OL 8 installation media provides "rsyslogd". This is a system utility providing support for message logging. Support for both internet and UNIX domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (which is a secure communications library implementing the SSL, TLS and DTLS protocols) provides a method to securely encrypt and offload auditing. 
 
Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above. 
 
Examples of each configuration follow: 
UDP *.* @remotesystemname 
TCP *.* @@remotesystemname 
RELP *.* :omrelp:remotesystemname:2514 
 
Note that a port number was given as there is no standard port for RELP.

'
  desc 'check', 'Verify the audit system offloads audit records onto a different system or media from the system being audited with the following command: 
 
$ sudo grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
 
/etc/rsyslog.conf:*.* @@[remoteloggingserver]:[port] 
 
If a remote server is not configured or the line is commented out, ask the System Administrator to indicate how the audit logs are offloaded to a different system or media.  
 
If there is no evidence that the audit logs are being offloaded to another system or media, this is a finding.'
  desc 'fix', 'Configure OL 8 to offload audit records onto a different system or media from the system being audited by specifying the remote logging server in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf" with the name or IP address of the log aggregation server. 
 
*.* @@[remoteloggingserver]:[port]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52248r780006_chk'
  tag severity: 'medium'
  tag gid: 'V-248814'
  tag rid: 'SV-248814r780008_rule'
  tag stig_id: 'OL08-00-030690'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-52202r780007_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
