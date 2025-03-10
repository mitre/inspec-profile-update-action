control 'SV-213911' do
  title 'The Database Master Key encryption password must meet DOD password complexity requirements.'
  desc 'Weak passwords may be easily guessed. When passwords are used to encrypt keys used for encryption of sensitive data, then the confidentiality of all data encrypted using that key is at risk.'
  desc 'check', "From the query prompt: 

SELECT name 
FROM [master].sys.databases 
WHERE state = 0 

Repeat for each database: 
From the query prompt: 
USE [database name] 
SELECT COUNT(name) 
FROM sys.symmetric_keys s, sys.key_encryptions k 
WHERE s.name = '##MS_DatabaseMasterKey##' 
AND s.symmetric_key_id = k.key_id 
AND k.crypt_type in ('ESKP', 'ESP2', 'ESP3')

If the value returned is zero, this is not applicable.

If the value returned is greater than zero, a Database Master Key exists and is encrypted with a password. 

Review procedures and evidence of password requirements used to encrypt Database Master Keys. 

If the passwords are not required to meet DoD password standards, currently a minimum of 15 characters with at least 1 upper-case character, 1 lower-case character, 1 special character, and 1 numeric character, and at least 8 characters changed from the previous password, this is a finding."
  desc 'fix', "Assign an encryption password to the Database Master Key that is a minimum of 15 characters with at least 1 upper-case character, 1 lower-case character, 1 special character, and 1 numeric character, and at least 8 characters changed from the previous password. 

To change the Database Master Key encryption password: 

USE [database name]; 
ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = '[new password]'; 

Note: The Database Master Key encryption method should not be changed until the effects are thoroughly reviewed. Changing the master key encryption causes all encryption using the Database Master Key to be decrypted and re-encrypted. This action should not be taken during a high-demand time. Please see the MS SQL Server documentation prior to re-encrypting the Database Master Key for detailed information."
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15129r313165_chk'
  tag severity: 'medium'
  tag gid: 'V-213911'
  tag rid: 'SV-213911r508025_rule'
  tag stig_id: 'SQL6-D0-001600'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-15127r313166_fix'
  tag 'documentable'
  tag legacy: ['V-79085', 'SV-93791']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
