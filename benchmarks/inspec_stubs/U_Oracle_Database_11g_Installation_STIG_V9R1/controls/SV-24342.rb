control 'SV-24342' do
  title 'The latest security patches should be installed.'
  desc 'Maintaining the currency of the software version protects the database from known vulnerabilities.'
  desc 'check', "Oracle provides patches in service patchsets, Critical Patch Updates (CPU) as well as providing patch set exceptions for installed DBMS products.

A patchset is an 'amended code set', consisting of a number of bug fixes, which is subjected to a rigorous QA and certification process. Oracle patch sets update the Oracle version number (e.g. 11.1.0.6 to 11.1.0.7) and are usually bundled together to support a product family (for example, Oracle DBMS includes Enterprise, Standard, Personal and Client Editions). This is covered in Check DG0001.

Oracle security patches are published quarterly in January, April, July and October as Critical Patch Updates (CPU). CPUs may be viewed at:

http://www.oracle.com/technology/deploy/security/alerts.htm

Most Oracle CPU patches are also listed in DoD IAVM alerts.

Patch set exceptions are fixes per a particular DBMS product based on reported bugs and do not undergo the rigorous QA and certification process that patchsets do. These are installed as needed to correct reported or observed bugs in Oracle DBMS products.

This check applies to the application of the CPU patches only. You must comply with Check DG0001 prior to applying Oracle Critical Patch Updates.

For Oracle Critical Patch Updates (CPU):

1. Go to the website http://www.oracle.com/technology/deploy/security/alerts.htm.
2. Click on the latest Critical Patch Update link.
3. Click on the [Database] link in the Supported Products and Components Affected section.
4. Enter your Oracle MetaLink credentials.
5. Locate the Critical Patch Update Availability table.
6. Identify your OS Platform and Oracle version to see if there is a CPU release.
7. If there is none, this check is Not a Finding. If there is one, note the patch number for the steps below.

View the installed patch numbers for the database using the Oracle opatch utility. 

On UNIX systems:   
  $ORACLE_HOME/OPatch/opatch lsinventory –detail | grep [PATCHNUM]

On Windows systems (From Windows Command Prompt):
  %ORACLE_HOME%\\OPatch\\opatch lsinventory –detail | findstr [PATCHNUM]

Replace [PATCHNUM] with the Patch number noted above. If the output shows the installed patch is present, this check is Not a Finding. No output indicates that the patch has not been applied and is a Finding."
  desc 'fix', 'Apply the most current Oracle Critical Patch update to the database software when available.

Follow vendor-provided patch installation instructions.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-26060r1_chk'
  tag severity: 'medium'
  tag gid: 'V-5659'
  tag rid: 'SV-24342r1_rule'
  tag stig_id: 'DG0003-ORACLE11'
  tag gtitle: 'DBMS security patch level'
  tag fix_id: 'F-16405r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
