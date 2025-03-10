control 'SV-256088' do
  title 'The Riverbed NetProfiler must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to apply the requirement only to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Go to Administration >> Appliance Security >> Security Compliance. 

Under "Operational Modes", verify "Strict Security Mode" is enabled. 

If it is not enabled, this is a finding.'
  desc 'fix', 'Go to Administration >> Appliance Security >> Security Compliance. 

Under "Operational Modes", enable "Strict Security Mode".'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59762r882770_chk'
  tag severity: 'medium'
  tag gid: 'V-256088'
  tag rid: 'SV-256088r882772_rule'
  tag stig_id: 'RINP-DM-000051'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-59705r882771_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
