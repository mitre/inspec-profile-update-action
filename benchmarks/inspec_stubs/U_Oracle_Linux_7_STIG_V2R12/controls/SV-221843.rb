control 'SV-221843' do
  title 'The Oracle Linux operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications.'
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

Ensure LDAP is configured to use TLS, by using the following command:

# grep -i "start_tls" /etc/sssd/sssd.conf
ldap_id_use_start_tls = true

If the "ldap_id_use_start_tls" option is not "true", this is a finding.'
  desc 'fix', 'Configure the operating system to implement cryptography to protect the integrity of LDAP authentication sessions.

Add or modify the following line in "/etc/sssd/sssd.conf":

ldap_id_use_start_tls = true'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36324r602566_chk'
  tag severity: 'medium'
  tag gid: 'V-221843'
  tag rid: 'SV-221843r877394_rule'
  tag stig_id: 'OL07-00-040180'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-36288r602567_fix'
  tag 'documentable'
  tag legacy: ['V-99425', 'SV-108529']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
