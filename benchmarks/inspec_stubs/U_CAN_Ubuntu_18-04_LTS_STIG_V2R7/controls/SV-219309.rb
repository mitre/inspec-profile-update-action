control 'SV-219309' do
  title 'The Ubuntu operating system must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.'
  desc 'Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', 'Verify the Ubuntu operating system is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance.

Check that "UsePAM" is set to yes in /etc/ssh/sshd_config:

# grep UsePAM /etc/ssh/sshd_config

UsePAM yes

If "UsePAM" is not set to "yes", this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to use strong authentication when establishing nonlocal maintenance and diagnostic sessions. 

Add or modify the following line to /etc/ssh/sshd_config

UsePAM yes'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21034r305255_chk'
  tag severity: 'medium'
  tag gid: 'V-219309'
  tag rid: 'SV-219309r610963_rule'
  tag stig_id: 'UBTU-18-010414'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-21033r305256_fix'
  tag 'documentable'
  tag legacy: ['V-100841', 'SV-109945']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
