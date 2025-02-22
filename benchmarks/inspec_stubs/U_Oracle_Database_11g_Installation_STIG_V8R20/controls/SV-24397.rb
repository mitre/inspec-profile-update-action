control 'SV-24397' do
  title 'Sensitive information stored in the database should be protected by encryption.'
  desc 'Sensitive data stored in unencrypted format within the database is vulnerable to unauthorized viewing.'
  desc 'check', "If no data is identified as being sensitive or classified by the Information Owner, in the System Security Plan or in the AIS Functional Architecture documentation, this check is Not a Finding.

If no identified sensitive or classified data requires encryption by the Information Owner in the System Security Plan and/or AIS Functional Architecture documentation, this check is Not a Finding.

Review sensitive data stored in the database as identified in the System Security Plan using select statements.

Note in the System Security Plan if the data is encrypted by column or by transparent encryption.

Transparent data encryption is available only in Oracle versions 10.2 and later using Oracle Advanced Security.

If transparent data encryption is specified, then verify it is enabled.

By data columns:

  From SQL*Plus:
    select owner, table_name, column_name from dba_encrypted_columns;

By tablespace:

  From SQL*Plus:
    select tablespace_name from dba_tablespaces where encrypted='YES';

If columns within tables, tables and/or tablespaces listed in the System Security Plan are required to be encrypted transparently are not listed above, this is a Finding.

If the DBMS products are used to encrypt data, view the sensitive data fields required to be encrypted using select statements.

If any data is displayed in human-readable format, this is a Finding.

If encryption is required by the information owner, NIST-certified cryptography is used to encrypt stored sensitive information. 

If encryption is required by the information owner, NIST-certified cryptography is used to encrypt stored classified non-sources and methods intelligence information.

If a classified enclave contains sources and methods intelligence data and is accessed by individuals lacking an appropriate clearance for sources and methods intelligence, then NSA-approved cryptography is used to encrypt all sources and methods intelligence stored within the enclave.

NOTE:  This check result may be marked not a Finding and the requirement of encryption in the database waived where the database has only database administrative accounts and application accounts that have a need-to-know to the data. This waiver does not preclude any requirement for encryption of the associated database data file (see DG0092)."
  desc 'fix', "Identify all sensitive data and the method to be used to encrypt specified sensitive data in the System Security Plan.

Use only NIST-certified or NSA-approved cryptography to provide encryption.

Oracle transparent data encryption (available in Oracle version 10.2 and later) requires Oracle Advanced Security.

See the chapter on Transparent Data Encryption in the Oracle Database Advanced Security Guide Administrator's Guide for details on using and configuring transparent data encryption.
  
Document acceptance of risk by the Information Owner where sensitive or classified data is not encrypted.

Have the Information Owner document assurance that the unencrypted sensitive or classified information is otherwise inaccessible to those without need-to-know access to the data.

Developers should consider using a record-specific encryption method to protect individual records.

For example, by employing the session username or other individualized element as part of the encryption key, then decryption of a data element is only possible by that user or other data accessible only by that user.  

Consider applying additional auditing of access to any unencrypted sensitive or classified data when accessed by unauthorized users (without need-to-know)."
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-26072r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15131'
  tag rid: 'SV-24397r1_rule'
  tag stig_id: 'DG0090-ORACLE11'
  tag gtitle: 'DBMS sensitive data identification and encryption'
  tag fix_id: 'F-26214r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
