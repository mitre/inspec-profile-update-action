control 'SV-217852' do
  title 'Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.'
  desc 'The Red Hat GPG keys are necessary to cryptographically verify packages are from Red Hat.'
  desc 'check', 'To ensure that the GPG keys are installed, run:

$ rpm -q gpg-pubkey

The command should return the strings below:

gpg-pubkey-fd431d51-4ae0493b
gpg-pubkey-2fa658e0-45700c69

If the Red Hat GPG Keys are not installed, this is a finding.'
  desc 'fix', 'To ensure the system can cryptographically verify base software packages come from Red Hat (and to connect to the Red Hat Network to receive them), the Red Hat GPG keys must be installed properly. To install the Red Hat GPG keys, run:

# rhn_register

If the system is not connected to the Internet or an RHN Satellite, then install the Red Hat GPG keys from trusted media such as the Red Hat installation CD-ROM or DVD. Assuming the disc is mounted in "/media/cdrom", use the following command as the root user to import them into the keyring:

# rpm --import /media/cdrom/RPM-GPG-KEY'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19333r376571_chk'
  tag severity: 'high'
  tag gid: 'V-217852'
  tag rid: 'SV-217852r603264_rule'
  tag stig_id: 'RHEL-06-000008'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-19331r376572_fix'
  tag 'documentable'
  tag legacy: ['V-38476', 'SV-50276']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
