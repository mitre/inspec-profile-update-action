control 'SV-252592' do
  title 'IBM Aspera Faspex must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized modification.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions, and limiting log data locations.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

This does not apply to audit logs generated on behalf of the device itself (management).

'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify that the log files for IBM Aspera Faspex have no world access. 

$ sudo find /opt/aspera/faspex/log/ \\( -perm -0001 -o -perm -0002 -o -perm -0004 \\) -print

If results are returned from the above command, this is a finding.'
  desc 'fix', 'Remove world access from any IBM Aspera Faspex log file that has world permissions granted. 

$ sudo chmod o-rwx <placefilenamehere>'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56048r817944_chk'
  tag severity: 'medium'
  tag gid: 'V-252592'
  tag rid: 'SV-252592r817946_rule'
  tag stig_id: 'ASP4-FA-050280'
  tag gtitle: 'SRG-NET-000098-ALG-000056'
  tag fix_id: 'F-55998r817945_fix'
  tag satisfies: ['SRG-NET-000098-ALG-000056', 'SRG-NET-000099-ALG-000057', 'SRG-NET-000100-ALG-000058']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
