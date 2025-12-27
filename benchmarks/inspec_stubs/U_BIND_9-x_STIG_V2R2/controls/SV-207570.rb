control 'SV-207570' do
  title 'Permissions assigned to the DNSSEC keys used with the BIND 9.x implementation must enforce read-only access to the key owner and deny access to all other users.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

The DNS server must protect the confidentiality and integrity of the DNSSEC keys and must protect the integrity of DNS information. There is no need to protect the confidentiality of DNS information because it is accessible by all devices that can contact the server.'
  desc 'check', 'If the server is in a classified network, this is Not Applicable.

Verify permissions assigned to the DNSSEC keys enforce read-only access to the key owner and deny access to group or system users:

With the assistance of the DNS Administrator, determine the location of the DNSSEC keys used by the BIND 9.x implementation:

# ls –al <DNSSEC_Key_Location>
-r--------. 1 named named 76 May 10 20:35 DNSSEC-example.key

If the key files are more permissive than 400, this is a finding.'
  desc 'fix', 'Change the permissions of the DNSSEC key files:

# chmod 400 <DNSSEC_key_file>'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7825r283764_chk'
  tag severity: 'medium'
  tag gid: 'V-207570'
  tag rid: 'SV-207570r612253_rule'
  tag stig_id: 'BIND-9X-001132'
  tag gtitle: 'SRG-APP-000231-DNS-000033'
  tag fix_id: 'F-7825r283765_fix'
  tag 'documentable'
  tag legacy: ['SV-87075', 'V-72451']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
