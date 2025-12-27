control 'SV-235161' do
  title 'The MySQL Database Server 8.0 must protect its audit configuration from unauthorized modification.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(Check users with permissions to administer MySQL Auditing.

select * from information_schema.user_privileges where privilege_type = 'AUDIT_ADMIN';

If unauthorized accounts have the AUDIT_ADMIN privilege, this is a finding.

Check that a keyring plugin is installed.
SELECT * FROM information_schema.PLUGINS where plugin_name like 'keyring%';

If no keyring is installed, this is a finding.

Check if the audit files are encrypted.

To check for data encryption at rest settings in MySQL:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables where variable_name = 'audit_log_encryption';

If "audit_log_encryption" is not set to "AES", this is a finding.)
  desc 'fix', %q(Remove audit-related permissions from individuals and roles not authorized to have them. 

REVOKE AUDIT_ADMIN on *.* FROM <user>;

Set audit log format to use AES encryption.
sudo vi /etc/my.cnf
[mysqld]
early-plugin-load=keyring_file.so
audit-log=FORCE_PLUS_PERMANENT
audit-log-format=JSON
audit-log-encryption=AES

Note: First instantiate the keyring plugin which is needed to store the audit encryption key.
The example above has an "early-plugin-load=keyring_file.so" entry in the my.cnf file.  
A keyring plugin must be present before adding the "audit-log-encryption=AES" entry or the database will not start.

Below are valid key ring plugins: 

For dev test - not encrypted
early-plugin-load=keyring_file.so

Encrypted file
early-plugin-load=keyring_encrypted_file.so
keyring_encrypted_file_data=/usr/local/mysql/mysql-keyring/keyring-encrypted
keyring_encrypted_file_password=password

KMIP
early-plugin-load=keyring_okv.so
keyring_okv_conf_dir=/usr/local/mysql/mysql-keyring-okv

Oracle Cloud Vault
early-plugin-load=keyring_oci.so
keyring_oci_user=ocid1.user.oc1..longAlphaNumericString
keyring_oci_tenancy=ocid1.tenancy.oc1..longAlphaNumericString
keyring_oci_compartment=ocid1.compartment.oc1..longAlphaNumericString
keyring_oci_virtual_vault=ocid1.vault.oc1.iad.shortAlphaNumericString.longAlphaNumericString
keyring_oci_master_key=ocid1.key.oc1.iad.shortAlphaNumericString.longAlphaNumericString
keyring_oci_encryption_endpoint=shortAlphaNumericString-crypto.kms.us-ashburn-1.oraclecloud.com
keyring_oci_management_endpoint=shortAlphaNumericString-management.kms.us-ashburn-1.oraclecloud.com
keyring_oci_vaults_endpoint=vaults.us-ashburn-1.oci.oraclecloud.com
keyring_oci_secrets_endpoint=secrets.vaults.us-ashburn-1.oci.oraclecloud.com
keyring_oci_key_file=file_name
keyring_oci_key_fingerprint=12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef

Hashicorp
early-plugin-load=keyring_hashicorp.so
keyring_hashicorp_role_id='ee3b495c-d0c9-11e9-8881-8444c71c32aa'
keyring_hashicorp_secret_id='0512af29-d0ca-11e9-95ee-0010e00dd718'
keyring_hashicorp_store_path='/v1/kv/mysql')
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38380r623603_chk'
  tag severity: 'medium'
  tag gid: 'V-235161'
  tag rid: 'SV-235161r879580_rule'
  tag stig_id: 'MYS8-00-008100'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-38343r623604_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
