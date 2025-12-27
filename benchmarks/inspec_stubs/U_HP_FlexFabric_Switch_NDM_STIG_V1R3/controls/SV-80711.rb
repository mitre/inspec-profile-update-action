control 'SV-80711' do
  title 'The HP FlexFabric Switch must map the authenticated identity to the user account for PKI-based authentication.'
  desc 'Authorization for access to any network device requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.'
  desc 'check', 'Determine if the HP FlexFabric Switch maps the authenticated identity to the user account for PKI-based authentication. 

[HP] display ssh user-information

 Total ssh users: 3
 Username            Authentication-type  User-public-key-name  Service-type
 pkiuser            password-publickey           hp                 all

If the HP FlexFabric Switch does not map the authenticated identity to the user account for PKI-based authentication, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to map the authenticated identity to the user account for PKI-based authentication.

Configure PKI entity:
[HP] pki entity HP
[HP-pki-entity-HP] common-name HP
[HP-pki-entity-HP] country US
[HP-pki-entity-HP] locality Littleton
[HP-pki-entity-HP] organization-unit STG
[HP-pki-entity-HP] organization HP
[HP-pki-entity-HP] state MA
[HP-pki-entity-HP] ip 15.252.76.101
[HP-pki-entity-HP] quit

Configure PKI domain:
[HP] pki domain HP
[HP-pki-domain-HP] certificate request entity HP
[HP-pki-domain-HP] public-key rsa general name hostkey
[HP-pki-domain-HP] source ip 15.252.76.101
[HP-pki-domain-HP] undo crl check enable
[HP-pki-domain-HP] quit

Submit certificate request on the switch:
[HP] pki request-certificate domain HP pkcs10

Transfer and import downloaded CA and user certificates to the switch:
[HP] pki import domain jitc pem ca filename rae-root-ca.cer
[HP] pki import domain jitc pem local filename HP.cer

Configure a local user:
[HP] local-user pkiuser
[HP-luser-pkiuser] service-type ssh
[HP-luser-pkiuser] authorization-attribute user-role network-admin
[HP-luser-pkiuser] password

Set this user as an SSH user and set authentication type to password-public key and assign pki domain:
[HP] ssh user pkiuser service-type all authentication-type password-publickey assign pki-domain hp

Note: Configuration required on the server side is not covered here.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66221'
  tag rid: 'SV-80711r1_rule'
  tag stig_id: 'HFFS-ND-000065'
  tag gtitle: 'SRG-APP-000177-NDM-000263'
  tag fix_id: 'F-72297r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
