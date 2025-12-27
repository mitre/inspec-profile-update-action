control 'SV-86179' do
  title 'The CA API Gateway must authenticate RADIUS endpoint devices before establishing a network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability. For network device management, this has been determined to be network management device addresses, SNMP authentication, and NTP authentication.'
  desc 'check', 'Using the "ssgconfig" menu subsystem, confirm RADIUS has been configured via 1) Configure system settings >> 4) Configure authentication method item 3 or 4. 

Confirm password is set to "Enter the RADIUS shared secret [<Hidden>]".

If RADIUS is not correctly configured, this is a finding.'
  desc 'fix', 'Using the ssgconfig menu subsystem, confirm RADIUS has been configured via 1) Configure system settings >> 4) Configure authentication method item 3 or 4. 

Configure radius/ladap_radius as required.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71555'
  tag rid: 'SV-86179r1_rule'
  tag stig_id: 'CAGW-DM-000280'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-77875r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
