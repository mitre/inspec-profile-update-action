control 'SV-96007' do
  title 'The WebSphere Application Server must prohibit or restrict the use of nonsecure ports, protocols, modules, and/or services as defined in the PPSM CAL and vulnerability assessments.'
  desc 'Some networking protocols may not meet organizational security requirements to protect data and components.

Application servers natively host a number of various features, such as management interfaces, httpd servers, and message queues. These features all run on TCPIP ports. This creates the potential that the vendor may choose to utilize port numbers or network services that have been deemed unusable by the organization. The application server must have the capability to both reconfigure and disable the assigned ports without adversely impacting application server operation capabilities. For a list of approved ports and protocols, reference the DoD ports and protocols website at https://powhatan.iiie.disa.mil/ports/cal.html.'
  desc 'check', 'In the administrative console, click Servers >> All Servers.

Select each [server_name].

Select >> Ports.

Confirm server ports are registered with PPSM.

Navigate to System Administration >> Deployment Manager >> Ports.

Confirm ports are registered with PPSM.

Navigate to System Administration >> node agents.

For each [node agent], select >> Ports.

Confirm ports are registered with PPSM.

If any of available ports are not registered with PPSM, or if those ports to be connected through the firewall are not approved by PPSM, this is a finding.'
  desc 'fix', 'Ensure all available ports are registered with PPSM.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80991r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81293'
  tag rid: 'SV-96007r1_rule'
  tag stig_id: 'WBSP-AS-000980'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-88075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
