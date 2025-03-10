control 'SV-24819' do
  title 'Asymmetric keys should use DoD PKI Certificates and be protected in accordance with NIST (unclassified data) or NSA (classified data) approved key management and processes.'
  desc 'Encryption is only effective if the encryption method is robust and the keys used to provide the encryption are not easily discovered. Without effective encryption, sensitive data is vulnerable to unauthorized access.'
  desc 'check', 'If Asymmetric keys are present and Oracle Advanced Security is not installed and operational on the DBMS host, this is a Finding.

For each asymmetric key identified as being used to encrypt sensitive data, verify the key owner is an application object owner or other non-DBA account.
 
If the key owner listed is a DBA, this is a Finding.

If any key owner is not the application object owner account or an account specific to the application as documented in the System Security Plan, this is a Finding.
  
If any asymmetric keys whose private key is not encrypted exist in the database, this is a Finding.

Review the access permissions to asymmetric keys.

Verify that any permission granted is authorized in the System Security Plan for access to the key.

Examine evidence that an audit record is created whenever the asymmetric key is accessed by other than authorized users. In particular, view evidence that access by a DBA or other system privileged account results in the generation of an audit record.

This is required because system privileges that allow access to encryption keys may be used to access sensitive data where the privileged user does not have a job function need-to-know the data.

If an audit record is not generated for unauthorized access to the asymmetric key, this is a Finding.'
  desc 'fix', 'Use DoD code-signing certificates to create asymmetric keys stored in the database that are used to encrypt sensitive data stored in the database.

Assign the application object owner account as the owner of asymmetric keys used by the application.

Create audit events for access to the key by other than the application owner account or approved application objects.

Revoke any privileges assigned to the asymmetric key to other than the application object owner account and authorized users.

Protect the private key by encrypting it with the database system master key where available.

Where available, store encryption keys and certificates on hardware security modules (HSM).

Oracle Advanced Security is required to provide asymmetric key management features.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29383r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15142'
  tag rid: 'SV-24819r1_rule'
  tag stig_id: 'DG0166-ORACLE11'
  tag gtitle: 'DBMS asymmetric key management'
  tag fix_id: 'F-26408r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
