control 'SV-240938' do
  title 'The vAMI must use the sfcb HTTPS port for communication with Lighttpd.'
  desc 'Some networking protocols may not meet organizational security requirements to protect data and components. Application servers natively host a number of various features, such as management interfaces, httpd servers and message queues. These features all run on TCPIP ports. This creates the potential that the vendor may choose to utilize port numbers or network services that have been deemed unusable by the organization. The application server must have the capability to both reconfigure and disable the assigned ports without adversely impacting application server operation capabilities. For a list of approved ports and protocols, reference the DoD ports and protocols web site at https://powhatan.iiie.disa.mil/ports/cal.html.'
  desc 'check', %q(At the command prompt, execute the following command to determine the sfcb HTTPS port:

 grep httpsPort /opt/vmware/etc/sfcb/sfcb.cfg | cut -d ':' -f 2 | tr -d ' '

If the httpsPort configuration is missing or commented out, this is a finding.

At the command prompt, type the following command to determine the port that Lighttpd is using to communicate with sfcb:

grep cimom -A 7 /opt/vmware/etc/lighttpd/lighttpd.conf | grep port | cut -d '=' -f 2 | tr -d '>' | tr -d ' ' | tr -d '"'

If Lighttpd is not using the sfcb HTTPS port for communication with  the vAMI, this is a finding.)
  desc 'fix', %q(At the command prompt, type the following command to determine the sfcb httpsPort:

 grep httpsPort /opt/vmware/etc/sfcb/sfcb.cfg | cut -d ':' -f 2 | tr -d ' '

Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.  Navigate to the '$HTTP["url"] =~ "^/cimom"' block.

Configure the lighttpd.conf file with the following block:

$HTTP["url"] =~ "^/cimom" {
    proxy.server = ( "" =>
                    ((
                      "host" => "127.0.0.1",
                      "port" => "<port>"
                    ))
                   )
}
Note: Substitute <port> in lighttpd.conf with the httpsPort number found in sfcb.cfg.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44171r676072_chk'
  tag severity: 'medium'
  tag gid: 'V-240938'
  tag rid: 'SV-240938r879588_rule'
  tag stig_id: 'VRAU-VA-000190'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-44130r676074_fix'
  tag 'documentable'
  tag legacy: ['SV-100869', 'V-90219']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
