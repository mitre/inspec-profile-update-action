control 'SV-237748' do
  title 'Oracle database products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.
Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the system documentation and interview the database administrator.

Identify all database software components.

Review the version and release information.
From SQL*Plus:

Select version from v$instance;

Access the vendor website or use other means to verify the version is still supported.
Oracle Release schedule:
https://support.oracle.com/knowledge/Oracle%20Database%20Products/742060_1.html

If the Oracle version or any of the software components are not supported by the vendor, this is a finding.'
  desc 'fix', 'Remove or decommission or all unsupported software products.

Upgrade unsupported DBMS or unsupported components to a supported version of the product. 

Oracle recommends the following upgrade options:

For product longevity and patching, Oracle strongly recommends upgrading to19c which is the Long Term Release with a support end date of April 30, 2027 (or April 30, 2024 if you choose not to pay Extended Support fees or purchase a ULA).
If you are currently running 12.1.x you will need to upgrade to the terminal release (12.1.0.2) for the DB Release you are running and then continue the upgrade process by upgrading to the 19c.
If you are currently running 12.2.0.1 or 18c, you should upgrade to 19c before the error correction grace periods for 12.2.0.1 and 18c expire.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40968r667276_chk'
  tag severity: 'medium'
  tag gid: 'V-237748'
  tag rid: 'SV-237748r667280_rule'
  tag stig_id: 'O121-BP-024750'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-40930r667277_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
