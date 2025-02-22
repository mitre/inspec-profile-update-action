control 'SV-207569' do
  title 'The DNSSEC keys used with the BIND 9.x implementation must be group owned by a privileged account.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

The DNS server must protect the confidentiality and integrity of the DNSSEC keys and must protect the integrity of DNS information. There is no need to protect the confidentiality of DNS information because it is accessible by all devices that can contact the server.'
  desc 'check', 'If the server is in a classified network, this is Not Applicable.

With the assistance of the DNS Administrator, identify all of the DNSSEC keys used by the BIND 9.x implementation.

Identify the account that the "named" process is running as:

# ps -ef | grep named
named 3015 1 0 12:59 ? 00:00:00 /usr/sbin/named -u named -t /var/named/chroot

With the assistance of the DNS Administrator, determine the location of the DNSSEC keys used by the BIND 9.x implementation.

# ls –al <DNSSEC_Key_Location>
-r--------. 1 named named 76 May 10 20:35 DNSSEC-example.key

If any of the DNSSEC keys are not group owned by the above account, this is a finding.'
  desc 'fix', 'Change the group ownership of the DNSSEC keys to the named process is running as.

# chgrp <named_proccess_group> <DNSSEC_key_file>.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7824r283761_chk'
  tag severity: 'medium'
  tag gid: 'V-207569'
  tag rid: 'SV-207569r612253_rule'
  tag stig_id: 'BIND-9X-001131'
  tag gtitle: 'SRG-APP-000231-DNS-000033'
  tag fix_id: 'F-7824r283762_fix'
  tag 'documentable'
  tag legacy: ['SV-87073', 'V-72449']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
