control 'SV-219543' do
  title 'Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.'
  desc 'This key is necessary to cryptographically verify packages that packages are from the operating system vendor.'
  desc 'check', 'To ensure that the GPG key is installed, run:

# rpm -qi gpg-pubkey-ec551f03 | gpg --keyid-format long | grep oracle.com | cut -f3 -d" " |cut -f2 -d"/"

The command should return the string below:

72F97B74EC551F03

If the operating system vendor GPG Key is not installed, this is a finding.'
  desc 'fix', "To ensure the system can cryptographically verify the software packages come from the operating system vendor (and connect to the vendor's network software repository to receive them if desired), the vendor GPG key must properly be installed. To ensure the GPG key is installed, run: 

# wget http://public-yum.oracle.com/RPM-GPG-KEY-oracle-ol6
# rpm --import RPM-GPG-KEY-oracle-ol6"
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21268r358169_chk'
  tag severity: 'high'
  tag gid: 'V-219543'
  tag rid: 'SV-219543r603263_rule'
  tag stig_id: 'OL6-00-000008'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-21267r358170_fix'
  tag 'documentable'
  tag legacy: ['SV-64895', 'V-50689']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
