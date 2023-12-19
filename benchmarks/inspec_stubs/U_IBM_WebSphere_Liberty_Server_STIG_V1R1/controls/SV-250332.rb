control 'SV-250332' do
  title 'The WebSphere Liberty Server must prohibit or restrict the use of nonsecure ports, protocols, modules, and/or services as defined in the PPSM CAL and vulnerability assessments.'
  desc 'Some networking protocols may not meet organizational security requirements to protect data and components.

Application servers natively host a number of various features, such as management interfaces, httpd servers, and message queues. These features all run on TCPIP ports. This creates the potential that the vendor may choose to use port numbers or network services that have been deemed unusable by the organization. The application server must have the capability to both reconfigure and disable the assigned ports without adversely impacting application server operation capabilities. For a list of approved ports and protocols, reference the DoD ports and protocols website at https://powhatan.iiie.disa.mil/ports/cal.html.'
  desc 'check', 'As a privileged user with access to the server.xml file, review the file and identify all TCPIP ports used by the server. 

EXAMPLE:
grep -I "port=" server.xml

 httpsPort="9443">

Review the PPSM site for the list of approved ports. If any of the ports used are not registered with PPSM, this is a finding.'
  desc 'fix', 'Every port listed in ${server.config.dir}/server.xml must be registered with PPSM. 

Refer to the PPSM website on https://cyber.mil/ppsm for information.'
  impact 0.5
  ref 'DPMS Target IBM WebSphere Liberty Server'
  tag check_id: 'C-53767r795047_chk'
  tag severity: 'medium'
  tag gid: 'V-250332'
  tag rid: 'SV-250332r795049_rule'
  tag stig_id: 'IBMW-LS-000370'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-53721r795048_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
