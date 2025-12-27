control 'SV-24817' do
  title 'DBMS symmetric keys should be protected in accordance with NSA or NIST-approved key management technology or processes.'
  desc 'Symmetric keys used for encryption protect data from unauthorized access. However, if not protected in accordance with acceptable standards, the keys themselves may be compromised and used for unauthorized data access.'
  desc 'check', 'If Symmetric keys are present and Oracle Advanced Security is not installed and operational on the DBMS host, this is a Finding.

If the symmetric key management procedures and configuration settings for the DBMS are not specified in the System Security Plan, this is a Finding.

If the procedures are not followed with evidence for audit, this is a Finding.

NOTE:  This check does not include a review of the key management procedures for validity. Specific key management requirements may be covered under separate checks.'
  desc 'fix', "Symmetric and other encryption keys require the following:
  -  protection from unauthorized access in transit and in storage
  -  utilization of accepted algorithms
  -  generation in accordance with required standards for the key's use
  -  expiration date
  -  continuity - key backup and recovery
  -  key change
  -  archival key storage (as necessary)

Details for key management requirements are provided by FIPS 140-2 key management standards available from NIST.

Oracle Advanced Security is required to provide symmetric key management features."
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29381r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15654'
  tag rid: 'SV-24817r1_rule'
  tag stig_id: 'DG0165-ORACLE11'
  tag gtitle: 'DBMS symmetric key management'
  tag fix_id: 'F-26406r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
