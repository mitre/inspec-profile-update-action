control 'SV-204581' do
  title 'The Red Hat Enterprise Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.'
  desc 'check', 'If LDAP is not being utilized, this requirement is Not Applicable.

Verify the operating system implements cryptography to protect the integrity of remote LDAP authentication sessions.

To determine if LDAP is being used for authentication, use the following command:

# systemctl status sssd.service
sssd.service - System Security Services Daemon
Loaded: loaded (/usr/lib/systemd/system/sssd.service; enabled; vendor preset: disabled)
Active: active (running) since Wed 2018-06-27 10:58:11 EST; 1h 50min ago

If the "sssd.service" is "active", then LDAP is being used. 

Determine the "id_provider" the LDAP is currently using:

# grep -i "id_provider" /etc/sssd/sssd.conf

id_provider = ad

If "id_provider" is set to "ad", this is Not Applicable.

Ensure that LDAP is configured to use TLS by using the following command:

# grep -i "start_tls" /etc/sssd/sssd.conf
ldap_id_use_start_tls = true

If the "ldap_id_use_start_tls" option is not "true", this is a finding.'
  desc 'fix', 'Configure the operating system to implement cryptography to protect the integrity of LDAP authentication sessions.

Add or modify the following line in "/etc/sssd/sssd.conf":

ldap_id_use_start_tls = true'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4705r88935_chk'
  tag severity: 'medium'
  tag gid: 'V-204581'
  tag rid: 'SV-204581r877394_rule'
  tag stig_id: 'RHEL-07-040180'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-4705r88936_fix'
  tag 'documentable'
  tag legacy: ['V-72227', 'SV-86851']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
