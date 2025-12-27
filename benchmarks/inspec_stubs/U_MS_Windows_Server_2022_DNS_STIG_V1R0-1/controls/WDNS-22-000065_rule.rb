control 'WDNS-22-000065_rule' do
  title 'The Windows 2022 DNS Server must protect secret/private cryptographic keys while at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and nonvolatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

The DNS server must protect the confidentiality and integrity of shared keys for TSIG and private keys for SIG(0) and must protect the integrity of DNS information. There is no need to protect the confidentiality of DNS information because it is accessible by all devices that can contact the server.'
  desc 'check', 'To verify the cryptographic keys are protected after being backed up to another medium (tape, disk, SAN, etc.), consult with the system administrator to determine the backup policy in place for the DNS server.

If a backup policy does not exist or the backup policy does not specify the protection required for the backup medium to be at or above the level as the server, this is a finding.'
  desc 'fix', 'To ensure the cryptographic keys are protected after being backed up to tape or other medium, develop a backup policy that includes the protection of backup date at or above the level as the DNS server.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000065_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000065'
  tag rid: 'WDNS-22-000065_rule'
  tag stig_id: 'WDNS-22-000065'
  tag gtitle: 'SRG-APP-000231-DNS-000033'
  tag fix_id: 'F-WDNS-22-000065_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
