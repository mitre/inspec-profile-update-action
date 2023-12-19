control 'SV-53299' do
  title 'Vendor-supported software and patches must be evaluated and patched against newly found vulnerabilities.'
  desc 'Security faults with software applications and operating systems are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Any time new software code is introduced to a system there is the potential for unintended consequences. There have been documented instances where the application of a patch has caused problems with system integrity or availability. Due to information system integrity and availability concerns, organizations must give careful consideration to the methodology used to carry out automatic updates.

If SQL Server were no longer supported, no patches from Microsoft would address newly discovered security vulnerabilities. Unpatched software is vulnerable to attack.'
  desc 'check', %q(Check Microsoft's list of supported SQL Server versions. To locate the correct web page, perform a web search for "Microsoft SQL Server end of support."

To be considered supported, Microsoft must report that the version is supported by security patches to known vulnerabilities.

Check SQL Server version by running the following command:
print @@version

If the security patch support for SQL Server cannot be determined or SQL Server version is not shown as supported, this is a finding.

If SQL Server does not contain the latest security patches, this is a finding.

SQL Server 2012 Service Pack 3 support end date: 10/9/2018
SQL Server 2012 Enterprise Core mainstream support end date: 7/11/2018
SQL Server 2012 Enterprise Core extended support end date: 7/12/2022)
  desc 'fix', 'Upgrade SQL Server to the Microsoft-supported version.

Apply the latest SQL Server patches after evaluation of impact.'
  impact 0.7
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47600r6_chk'
  tag severity: 'high'
  tag gid: 'V-40945'
  tag rid: 'SV-53299r4_rule'
  tag stig_id: 'SQL2-00-015700'
  tag gtitle: 'SRG-APP-000133-DB-000205'
  tag fix_id: 'F-46227r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
