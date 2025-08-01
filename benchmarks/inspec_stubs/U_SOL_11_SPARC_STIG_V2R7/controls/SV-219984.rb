control 'SV-219984' do
  title 'The operating system must protect the integrity of transmitted information.'
  desc 'Ensuring the integrity of transmitted information requires the operating system take feasible measures to employ transmission layer security. This requirement applies to communications across internal and external networks.'
  desc 'check', 'The operator shall determine if IPsec is being used to encrypt data for activities such as cluster interconnects or other non-SSH, SFTP data connections.

On both systems review the file /etc/inet/ipsecinit.conf. Ensure that connections between hosts are configured properly in this file per the Solaris 11 documentation.

Check that the IPsec policy service is online:

# svcs svc:/network/ipsec/policy:default

If the IPsec service is not online, this is a finding.

If encrypted protocols are not used between systems, this is a finding.'
  desc 'fix', 'The Service Management profile is required.

Configure IPsec encrypted tunneling between two systems.

On both systems review the file /etc/inet/ipsecinit.conf. Ensure that connections between hosts are configured properly in this file per the Solaris 11 documentation.

Ensure that the IPsec policy service is online:

Enable the IPsec service:

# svcadm enable svc:/network/ipsec/policy:default'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21694r371336_chk'
  tag severity: 'medium'
  tag gid: 'V-219984'
  tag rid: 'SV-219984r854543_rule'
  tag stig_id: 'SOL-11.1-060190'
  tag gtitle: 'SRG-OS-000423'
  tag fix_id: 'F-21693r371337_fix'
  tag 'documentable'
  tag legacy: ['V-48141', 'SV-61013']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
