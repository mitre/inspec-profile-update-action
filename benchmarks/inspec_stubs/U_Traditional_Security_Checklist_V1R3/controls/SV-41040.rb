control 'SV-41040' do
  title 'Industrial Security - Contractor Visit Authorization Letters (VALs)'
  desc 'Failure to require Visit Authorization Letters (VALs) for contractor visits could result in sensitive or classified materials being released to unauthorized personnel.

REFERENCES:

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PE-2, PE-2(1), PE- 3, , PE-8, PS-3(1), PS-6(2)

DoD Manual 5200.01, Volume 1, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 2, para 9.k., 9.l. & 9.m.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 2, para 7.a.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 6.'
  desc 'check', %q(1. Check with the security manager or personnel security specialists to ensure there are written procedures for  contractors visiting government sites. 

2. Ask to see copies of the site VALs and/or determine site VAL process based on the processing of contractors on your inspection team.  

3. Ensure all government facilities have a VAL on file for all contractors visiting the site - to include permanent party contractors.  

NOTES: 

1. JPAS should and will likely be used for most short term "visitor" VALs; however, in addition to JPAS the VAL may also be passed via hard copy or electronically using email (mail, fax, email) for "assigned" contractor employees. This is because JPAS is by design intended for short term visits; whereas, contractor "employee" VALs should require additional information (such as contract number, COR identification, etc.) that cannot be input or passed via JPAS. Lack of a hard copy VAL alone for assigned contractor employees at a site will not necessarily be cause for a finding if a VAL in JPAS is available.  Reviewers must use discretion when evaluating if the lack of hard copy VAL has caused any substantive confusion over the company Facility Clearance Level (FCL), individual contract employee security clearance levels, IT position assignments based on job descriptions (found in applicable Statements of Work (SOW and/or DD 254), etc. when deciding if a finding is warranted. For instance an individual employee's JPAS access might indicate they have TS clearance - but the FCL for the company is only at the Secret level and/or the contract only allows for up to Secret access.  If the site is allowing access to TS for this individual - then the lack of a hard copy VAL could be cited as a finding, in addition to any other related findings for this discovery.

2. Applies in a tactical environment if contract personnel visit or are assigned.

3. Reviewers should be sure to note in the findings report if the finding concerns JPAS issues for short term contractor visitors or if it concerns "hard copy" VALs for assigned contractor employees.)
  desc 'fix', '1. Written procedures must be developed that cover the requirements and process for Visit Authorization Letters (VAL) for contractors visiting and/or employed at government sites. 

2. All government sites must have a VAL on file for each contractor visiting the site temporarily and also for permanent party contractors routinely working/physically employed at the site.  

NOTES: 

JPAS should be used for most short term "visitor" VALs; however, in addition to JPAS (or as an alternative to JPAS for contractors who do not have JPAS accounts) VALs may also be passed via hard copy or electronically using email (mail, fax, email) for "assigned" contractor employees.  This is because JPAS is by design intended for short term visits; whereas, contractor  "employee" VALs require additional information (such as contract number, COR identification, etc.) that cannot be input or passed via JPAS.  

A hard copy VAL for assigned contractor employees will help to eliminate substantive confusion over the company Facility Clearance Level (FCL), individual contract employee security clearance levels, IT position assignments based on job descriptions (found in applicable Statements of Work (SOW and/or DD 254), etc.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39661r3_chk'
  tag severity: 'low'
  tag gid: 'V-30994'
  tag rid: 'SV-41040r3_rule'
  tag stig_id: 'ID-02.03.01'
  tag gtitle: 'Industrial Security - Contractor VALs'
  tag fix_id: 'F-34806r5_fix'
  tag 'documentable'
end
