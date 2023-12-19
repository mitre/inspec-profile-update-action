control 'SV-213603' do
  title 'The EDB Postgres Advanced Server must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', 'If a FIPS-certified OpenSSL library is not installed and configured, this is a finding.

Run this command to ensure that you are running RHEL: "cat /etc/redhat-release"

Run this command to see the OpenSSL version: "openssl version"

If "/etc/redhat-release" does not show a supported version of Red Hat Enterprise Linux or if the openssl version does not include "-fips" in the version, this is a finding.'
  desc 'fix', 'There is no known fix for a FIPS-compliant OpenSSL library on Microsoft Windows at this time.

Configure RHEL OpenSSL as defined in section 9.1 of the RHEL OpenSSL FIPS Compliance documentation here:

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14825r290121_chk'
  tag severity: 'high'
  tag gid: 'V-213603'
  tag rid: 'SV-213603r508024_rule'
  tag stig_id: 'PPS9-00-004900'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-14823r290122_fix'
  tag 'documentable'
  tag legacy: ['V-68959', 'SV-83563']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
