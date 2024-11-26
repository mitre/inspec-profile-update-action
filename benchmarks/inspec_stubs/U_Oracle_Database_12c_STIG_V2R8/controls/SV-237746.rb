control 'SV-237746' do
  title 'The OS must limit privileges to change the DBMS software resident within software libraries (including privileged programs).'
  desc 'When dealing with change control issues, it should be noted, any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

If the application were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement is contingent upon the language in which the application is programmed, as many application architectures in use today incorporate their software libraries into, and make them inseparable from, their compiled distributions, rendering them static and version-dependent.  However, this requirement does apply to applications with software libraries accessible and configurable as in the case of interpreted languages.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

The DBMS software libraries contain the executables used by the DBMS to operate. Unauthorized access to the libraries can result in malicious alteration. This may in turn jeopardize data stored in the DBMS and/or operation of the host system.'
  desc 'check', 'Review permissions that control access to the DBMS software libraries. The software library location may be determined from vendor documentation or service/process executable paths.

Typically, only the DBMS software installation/maintenance account or SA account requires access to the software library for operational support such as backups. Any other accounts should be scrutinized and the reason for access documented. Accounts should have the least amount of privilege required to accompTypically, only the DBMS software installation/maintenance account or SA account requires access to the software library for operational support such as backups. Any other accounts should be scrutinized and the reason for access documented. Accounts should have the least amount of privilege required to accomplish the job.

Below is one example for how to review accounts with access to software libraries for a Linux-based system:
cat /etc/group |grep -i dba
--Example output:
dba:x:102: 

--take above number and input in below grep command
cat /etc/passwd |grep 102

If any accounts are returned that are not required and authorized to have access to the software library location do have access, this is a finding.'
  desc 'fix', 'Restrict access to the DBMS software libraries to accounts that require access based on job function.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40965r917647_chk'
  tag severity: 'medium'
  tag gid: 'V-237746'
  tag rid: 'SV-237746r917648_rule'
  tag stig_id: 'O121-OS-011200'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-40928r667269_fix'
  tag 'documentable'
  tag legacy: ['V-61869', 'SV-76359']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
