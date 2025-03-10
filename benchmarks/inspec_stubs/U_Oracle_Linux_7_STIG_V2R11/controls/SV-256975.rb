control 'SV-256975' do
  title 'The Oracle Linux operating system must ensure cryptographic verification of vendor software packages.'
  desc 'Cryptographic verification of vendor software packages ensures that all software packages are obtained from a valid source and protects against spoofing that could lead to installation of malware on the system. Oracle cryptographically signs all software packages, which includes updates, with a GPG key to verify that they are valid.'
  desc 'check', 'Confirm Oracle package-signing key is installed on the system and verify its fingerprint matches vendor value.

Note: The GPG key is defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-oracle" by default.

List Oracle GPG keys installed on the system:

     $ sudo rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "oracle"

     gpg(Oracle OSS group (Open Source Software group) <build@oss.oracle.com>)

If Oracle GPG key is not installed, this is a finding.

List key fingerprint of installed Oracle GPG key:

     $ sudo gpg -q --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle

If key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-oracle" is missing, this is a finding.

Example output:

     pub  2048R/EC551F03 2010-07-01 Oracle OSS group (Open Source Software group) <build@oss.oracle.com>
           Key fingerprint = 4214 4123 FECF C55B 9086  313D 72F9 7B74 EC55 1F03
	   
Compare key fingerprint of installed Oracle GPG key with fingerprint listed for OL 7 on Oracle verification webpage at https://linux.oracle.com/security/gpg/#gpg.

If key fingerprint does not match, this is a finding.'
  desc 'fix', 'Install Oracle package-signing key on the system and verify its fingerprint matches vendor value.

Insert OL 7 installation disc or attach OL 7 installation image to the system. Mount the disc or image to make the contents accessible inside the system.

Assuming the mounted location is "/media/cdrom", use the following command to copy Oracle GPG key file onto the system:

     $ sudo cp /media/cdrom/RPM-GPG-KEY-oracle /etc/pki/rpm-gpg/
	 
Import Oracle GPG keys from key file into system keyring:

     $ sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-oracle
	 
Using the steps listed in the Check Text, confirm the newly imported key shows as installed on the system and verify its fingerprint matches vendor value.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-60653r902760_chk'
  tag severity: 'medium'
  tag gid: 'V-256975'
  tag rid: 'SV-256975r902762_rule'
  tag stig_id: 'OL07-00-010019'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-60595r902761_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
