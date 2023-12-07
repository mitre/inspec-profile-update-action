control 'SV-83215' do
  title 'The Windows 2008 DNS Server must protect secret/private cryptographic keys while at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

The DNS server must protect the confidentiality and integrity of shared keys (for TSIG) and private keys (for SIG(0)) and must protect the integrity of DNS information. There is no need to protect the confidentiality of DNS information because it is accessible by all devices that can contact the server.'
  desc 'check', 'To ensure the cryptographic keys are protected after being backed up to another medium (tape, disk, SAN, etc.), consult with the System Administrator to determine the backup policy in place for the DNS Server.

Determine how and where backed up data is being stored. 

Verify the protection of the backup medium is secured to the same level, or higher, as the server itself.

If a backup policy does not exist or the backup policy does not specify the protection required for backup medium to be at or above the same level as the server, this is a finding.'
  desc 'fix', 'To ensure the cryptographic keys are protected after being backed up to tape or other medium, develop a backup policy to include the protection of backup date to be at or above the same level as the DNS server itself.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59565r3_chk'
  tag severity: 'medium'
  tag gid: 'V-58693'
  tag rid: 'SV-83215r1_rule'
  tag stig_id: 'WDNS-SC-000024'
  tag gtitle: 'SRG-APP-000231-DNS-000033'
  tag fix_id: 'F-64077r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
