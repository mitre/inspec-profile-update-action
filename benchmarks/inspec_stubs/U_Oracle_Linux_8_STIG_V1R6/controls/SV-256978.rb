control 'SV-256978' do
  title 'OL 8 must ensure cryptographic verification of vendor software packages.'
  desc 'Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Oracle cryptographically signs all software packages, which includes updates, with a GPG key to verify that they are valid.'
  desc 'check', 'Confirm Oracle package-signing key is installed on the system and verify its fingerprint matches vendor value.

Note: The GPG key is defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-oracle" by default.

List Oracle GPG keys installed on the system:

     $ sudo rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "oracle"

     gpg(Oracle OSS group (Open Source Software group) <build@oss.oracle.com>)

If Oracle GPG key is not installed, this is a finding.

List key fingerprint of installed Oracle GPG key:

     $ sudo gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle

If key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-oracle" is missing, this is a finding.

Example output:

     pub   rsa4096/AD986DA3 2019-04-09 [SC] [expires: 2039-04-04]
           Key fingerprint = 76FD 3DB1 3AB6 7410 B89D  B10E 8256 2EA9 AD98 6DA3
     uid                   Oracle OSS group (Open Source Software group) <build@oss.oracle.com>
     sub   rsa4096/D95DC12B 2019-04-09 [E] [expires: 2039-04-04]

	   
Compare key fingerprint of installed Oracle GPG key with fingerprint listed for OL 8 on Oracle verification webpage at https://linux.oracle.com/security/gpg/#gpg.

If key fingerprint does not match, this is a finding.'
  desc 'fix', 'Install Oracle package-signing key on the system and verify its fingerprint matches vendor value.

Insert OL 8 installation disc or attach OL 8 installation image to the system. Mount the disc or image to make the contents accessible inside the system.

Assuming the mounted location is "/media/cdrom", use the following command to copy Oracle GPG key file onto the system:

     $ sudo cp /media/cdrom/RPM-GPG-KEY-oracle /etc/pki/rpm-gpg/
	 
Import Oracle GPG keys from key file into system keyring:

     $ sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
	 
Using the steps listed in the Check Text, confirm the newly imported key shows as installed on the system and verify its fingerprint matches vendor value.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-60656r902782_chk'
  tag severity: 'medium'
  tag gid: 'V-256978'
  tag rid: 'SV-256978r902784_rule'
  tag stig_id: 'OL08-00-010019'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-60598r902783_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
