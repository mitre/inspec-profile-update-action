control 'SV-24339' do
  title 'Vendor supported software is evaluated and patched against newly found vulnerabilities.'
  desc 'Unsupported software versions are not patched by vendors to address newly discovered security versions. An unpatched version is vulnerable to attack.'
  desc 'check', "From SQL*Plus:
  select banner from v$version where banner like 'Oracle%';

The currently supported Oracle 11g version as of 07/2015 is:

11.2 - Premier Support for 11.2 ended 31 Jan 2015; Extended Support is free for one year thereafter.
Extended Support for 11.2 ends 31 Jan 2018.
Sustaining Support for 11.2 available after 31 Jan 2018.

If the Oracle 11 (or earlier) version is not in the list above or is not supported with a purchased extended support contract, this is a finding.

Note: Sustaining Support does not include security updates. Any product in Sustaining Support is a finding.

A patchset is an 'amended code set', consisting of a number of bug fixes, which is subjected to a rigorous QA and certification process.

Oracle patch sets update the Oracle version number (e.g. 10.2.0.3 to 10.2.0.4) and are usually bundled together to support a product family (for example, Oracle DBMS includes Enterprise, Standard, Personal and Client Editions).

The only supported patched version as of 08/28/2015 is 11.2.0.4.

If the Oracle patchset level is less than 11.2.0.4, this is a finding.

Note: a separate STIG exists for Oracle Database 11.2g."
  desc 'fix', 'Upgrade to a supported Oracle version. Purchase an Oracle Extended Support Contract where required.

See http://www.oracle.com/technology/support/patches.htm for a definitive list of version patch sets for Oracle DBMS software.

See http://www.oracle.com/support/library/brochure/lifetime-support-technology.pdf for Oracle support policies and timelines.'
  impact 0.7
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-28293r6_chk'
  tag severity: 'high'
  tag gid: 'V-5658'
  tag rid: 'SV-24339r2_rule'
  tag stig_id: 'DG0001-ORACLE11'
  tag gtitle: 'The Database version is unsupported.'
  tag fix_id: 'F-22570r1_fix'
  tag responsibility: 'Information Assurance Officer'
end
