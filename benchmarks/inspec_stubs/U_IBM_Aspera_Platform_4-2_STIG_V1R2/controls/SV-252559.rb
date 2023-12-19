control 'SV-252559' do
  title 'The IBM Aspera Console must protect audit information from unauthorized read access.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured network element. Thus, it is imperative that the collected log data from the various network elements, as well as the auditing tools, be secured and can only be accessed by authorized personnel.

This does not apply to audit logs generated on behalf of the device itself (management).

'
  desc 'check', 'Verify the log files for IBM Aspera Console do not have world access with the following command:

$ sudo find /opt/aspera/console/log/ \\( -perm -0001 -o -perm -0002 -o -perm -0004 \\) -print

If results are returned from the above command, this is a finding.'
  desc 'fix', 'Remove world access from any IBM Aspera Console log file that has world permissions granted. 

$ sudo chmod o-rwx <placefilenamehere>'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56015r817845_chk'
  tag severity: 'medium'
  tag gid: 'V-252559'
  tag rid: 'SV-252559r817847_rule'
  tag stig_id: 'ASP4-CS-040120'
  tag gtitle: 'SRG-NET-000098-ALG-000056'
  tag fix_id: 'F-55965r817846_fix'
  tag satisfies: ['SRG-NET-000098-ALG-000056', 'SRG-NET-000099-ALG-000057', 'SRG-NET-000100-ALG-000058']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
