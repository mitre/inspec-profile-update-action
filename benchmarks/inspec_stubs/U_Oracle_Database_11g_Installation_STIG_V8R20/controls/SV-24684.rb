control 'SV-24684' do
  title 'Database data files containing sensitive information should be encrypted.'
  desc 'Where system and DBMS access controls do not provide complete protection of sensitive or classified information, the Information Owner may require encryption to provide additional protection. Encryption of sensitive data helps protect disclosure to privileged users who do not have a need-to-know requirement to the data, but may be able to access DBMS data files using OS file tools.

NOTE:  The decision to encrypt data is the responsibility of the Information Owner and should be based on other access controls employed to protect the data.'
  desc 'check', 'Review the System Security Plan and/or the AIS Functional Architecture documentation to discover sensitive or classified data identified by the Information Owner that requires encryption.
 
If no sensitive or classified data is identified as requiring encryption by the Information Owner, this check is Not a Finding.

Have the DBA use select statements in the database to review sensitive data stored in tables as identified in the System Security Plan and/or AIS Functional Architecture documentation.

If all sensitive data as identified is encrypted within the database objects, encryption of the DBMS data files is optional and Not a Finding.

If all sensitive data is not encrypted within database objects, review encryption applied to the DBMS host data files.

If no encryption is applied, this is a Finding.

If encryption is required by the information owner, NIST-certified cryptography is used to encrypt stored sensitive information. 

If encryption is required by the information owner, NIST-certified cryptography is used to encrypt stored classified non-sources and methods intelligence information.

If a classified enclave contains sources and methods intelligence data and is accessed by individuals lacking an appropriate clearance for sources and methods intelligence, then NSA-approved cryptography is used to encrypt all sources and methods intelligence stored within the enclave.

Determine which DBMS data files contain sensitive data. Not all DBMS data files will require encryption.'
  desc 'fix', 'Use third-party tools or native DBMS features to encrypt sensitive or classified data stored in the database.

Use only NIST-certified or NSA-approved cryptography to provide encryption.

Document acceptance of risk by the Information Owner where sensitive or classified data is not encrypted.

Have the IAO document assurance that the unencrypted sensitive or classified information is otherwise inaccessible to those who do not have Need-to-Know access to the data.

To lessen the impact on system performance, separate sensitive data where file encryption is required into dedicated DBMS data files.

Consider applying additional auditing of access to any unencrypted sensitive or classified data when accessed by users (with and/or without Need-to-Know).'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29216r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15132'
  tag rid: 'SV-24684r1_rule'
  tag stig_id: 'DG0092-ORACLE11'
  tag gtitle: 'DBMS data file encryption'
  tag fix_id: 'F-26237r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
